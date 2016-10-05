type CrestAuthData
	requestState::AbstractString
	server::HttpServer.Server
	authResponse::Dict

	CrestAuthData(requestState::AbstractString) = new(requestState)
end

authorization_received(authData::CrestAuthData) = isdefined(authData, :authResponse)

function server_task(authData::CrestAuthData, req::HttpServer.Request, res::HttpServer.Response)
	resp = HttpServer.Response()
	resp.headers["Connection"] = "close"
	if startswith(req.resource, "/?")
		query = HttpServer.parsequerystring(req.resource[3:end])
		if isa(query, Associative) && get(query, "state", "") == authData.requestState
			authData.authResponse = query
			resp.data = "Authorization data received, thank you"
		end
	elseif req.resource == "/"
		# When we're requesting a token, it arrives in the browser as a fragment that is not sent to our HTTP server
		# So in this case we send a script that will reload the page, forwarding the fragment as a resource
		resp.data =
			"""
			Redirecting authorization fragment to Julia
			<script type="text/javascript">
				if (window.location.hash) {
					var loc = window.location.toString().replace("#", "?")
					window.location.replace(loc)
				}
			</script>
			"""
	end
	return resp
end

function run_server(authData::CrestAuthData, port::UInt16)
	http = HttpServer.HttpHandler((req, res)->server_task(authData, req, res))
	authData.server = HttpServer.Server(http)
	@async run(authData.server; port = port)
end

function stop_server(authData::CrestAuthData)
	close(authData.server)
	yield()
end

function request_access_url(authData::CrestAuthData, appInfo::Dict)
	params = Dict("response_type" => get(appInfo, "secretKey", "") != "" ? "code" : "token",
			  "redirect_uri" => appInfo["callbackURL"],
			  "client_id" => appInfo["clientID"],
			  "scope" => appInfo["scope"],
			  "state" => authData.requestState)
	queryStr = Requests.format_query_str(params)
	return "https://login.eveonline.com/oauth/authorize/?$queryStr"
end

function open_browser(url::AbstractString)
    if is_windows()
	    url = replace(url, "&", "^&") # escape & on windows
	    run(`cmd /c start $url`)
    else
      spawn(`xdg-open "$url"`)
    end
end

function request_authorization_token(endpoint::AbstractString, appInfo::Dict, code::AbstractString, refresh::Bool)
	authStr = base64encode(appInfo["clientID"] * ":" * appInfo["secretKey"])
	if refresh
		params = Dict("grant_type" => "refresh_token",
				  "refresh_token" => code)
	else
		params = Dict("grant_type" => "authorization_code",
				  "code" => code)
	end
	dataStr = Requests.format_query_str(params)
	resp = Requests.post(endpoint;
	                     data=dataStr,
						 headers=Dict{Any, Any}("Authorization" => "Basic $authStr",
						          "Content-Type" => "application/x-www-form-urlencoded"))
	return JSON.parse(String(resp.data))
end

function request_access(endpoint::AbstractString, appInfo::Dict)
	authFile = joinpath(cacheDir, "authorization.json")
	auth = json_read(authFile)
	authTime = stat(authFile).mtime
	if auth != nothing && time() - authTime <= get(auth, "expires_in", 0) / 2
		# We have an auth token that still has half of its validity period to go
		return auth
	end
	if auth == nothing || !haskey(auth, "refresh_token") || get(appInfo, "secretKey", "") == ""
		authData = CrestAuthData("crestauth.jl$(rand(UInt))")
		uri = URIParser.URI(appInfo["callbackURL"])
		port = uri.port
		if port == 0
			port = uri.schema=="https"? 443 : 80
		end
		run_server(authData, port)
		open_browser(request_access_url(authData, appInfo))
		while !authorization_received(authData)
			yield()
		end
		stop_server(authData)
		if haskey(authData.authResponse, "code")
			auth = request_authorization_token(endpoint, appInfo, authData.authResponse["code"], false)
		else
			auth = Dict{AbstractString, Any}(authData.authResponse)
			auth["expires_in"] = parse(get(auth, "expires_in", "0"))
			delete!(auth, "state")
		end
		json_write(authFile, auth)
	else
		auth = request_authorization_token(endpoint, appInfo, auth["refresh_token"], true)
	end
	return auth
end
