function cp_file(file, srcDir, dstDir)
  srcFile = joinpath(srcDir, file)
  dstFile = joinpath(dstDir, file)
  !isfile(dstFile) && cp(srcFile, dstFile; remove_destination = true)
end

function create_cfg()
  srcDir = dirname(@__FILE__)
  cfgDir = joinpath(srcDir, "cfg")
  !isdir(cfgDir) && mkdir(cfgDir)
  cp_file("appinfo.json", srcDir, cfgDir)
  cp_file("config.json", srcDir, cfgDir)
end

create_cfg()
