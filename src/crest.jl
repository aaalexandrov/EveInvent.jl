# const urlCrest = "https://public-crest.eveonline.com/"
const urlCrest = "https://crest-tq.eveonline.com/"

const urlReplace = Dict{Char, Char}('/'=>'-', '?'=>'.')
url_to_filename(url::AbstractString) = replace(replace(url, urlCrest[1:end-1], ""), collect(keys(urlReplace)), c->urlReplace[c[1]]) * ".json"

int_keys(assoc::Associative) = Dict(parse(Int, k)=>v for (k,v) in assoc)

function json_read(fileName::AbstractString)
	data = nothing
	try
		open(fileName, "r") do s
			data = JSON.parse(s)
		end
	catch e
		if !isa(e, SystemError)
			rethrow()
		end
	end
	if isa(data, Associative)
		intKeys = all(keys(data)) do k
			try
				parse(Int, k)
				return true
			catch
				return false
			end
		end
		if intKeys
			data = int_keys(data)
		end
	end
	return data
end

function json_write(fileName::AbstractString, data; indent::Int = 2)
	open(fileName, "w+") do s
		JSON.print(s, data, indent)
	end
end

function read_from_cache(url::AbstractString, timeout::Float64)
	fileName = joinpath(cacheDir, url_to_filename(url))
	data = json_read(fileName)
	if time() - mtime(fileName) >= timeout
		data = nothing
	end
	return data
end

function write_to_cache(url::AbstractString, data)
	if !isdir(cacheDir)
		mkdir(cacheDir)
	end
	fileName = joinpath(cacheDir, url_to_filename(url))
	json_write(fileName, data)
	nothing
end

function clear_cache(ext::AbstractString)
	if isdir(cacheDir)
		map(f->endswith(f, ext) && rm(joinpath(cacheDir, f)), readdir(cacheDir))
	end
end

function get_crest(url::AbstractString, auth, timeoutHours::Float64 = convert(Float64, Inf))
	res = read_from_cache(url, timeoutHours * 60 * 60)
	if res != nothing
		return res
	end
	local queryRes
	orgUrl = url
	headers = Dict{AbstractString, AbstractString}()
	if auth != nothing
		headers["Authorization"] = auth["token_type"]*" "*auth["access_token"]
	end
	while true
		info("GET from $url")
		resp = Requests.get(url; headers=headers)
		if resp.status != 200
			info("Response status: $(resp.status)")
			return nothing
		end
		queryRes = JSON.parse(String(resp.data))
		if res == nothing
			res = queryRes
		else
			append!(res["items"], queryRes["items"])
		end
		if !haskey(queryRes, "next")
			break
		end
		url = queryRes["next"]["href"]
	end
	@assert !haskey(queryRes, "totalcount") || queryRes["totalcount"] == length(res["items"])
	if haskey(res, "items")
		res = res["items"]
	end
	write_to_cache(orgUrl, res)
	return res
end
