require 'dbi'
require 'digest/sha1'

class Redminesvnauth 

$disable_svn=:false
@dbuser="redmine"
@dbpass="PutPasswordHere"
@dbh
def initialize
@dbuser="redmine"
@dbpass="PutPasswordHere"
end

def debug(req)
	$stderr.puts(req.get_basic_auth_pw)
	$stderr.puts(req.user)
	$stderr.puts(req.uri)
	$stderr.puts(req.filename)
	$stderr.puts(req.path_info)
end

#access
def check_access(req)
return processreq(req)
	return Apache::FORBIDDEN if $disable_svn==:true
$stderr.puts "Ruby Access!"
$stderr.puts(req.remote_logname)
	$stderr.puts(req.get_basic_auth_pw)
	$stderr.puts(req.user)
	$stderr.puts(req.path_info)
return Apache::OK
end
#authen
def authenticate(req)
return processreq(req)
	return Apache::FORBIDDEN if $disable_svn==:true
$stderr.puts "authenticate"
	if req.user != "matthb2" then 
		return Apache::FORBIDDEN
	end
	return Apache::OK
end
#authz
def authorize(req)
return processreq(req)
	return Apache::FORBIDDEN if $disable_svn==:true
$stderr.puts "authorize"
$stderr.puts(req.remote_logname)
	return Apache::OK
end

def opendb
@dbh=DBI.connect("DBI:Mysql:redmine:localhost",@dbuser,@dbpass)
end
def closedb
@dbh.disconnect if @dbh
end
def processreq(req)
	$stderr.puts "Authenticated"
	#debug(req)
	$stderr.puts req.remote_host
	$stderr.puts req.hostname
#	if req.remote_host == req.hostname.split(".")[0] then
	if req.remote_host == req.hostname then
		return Apache::OK #let the repo viewer work
	end
	self.opendb
	pass=Digest::SHA1.hexdigest(req.get_basic_auth_pw || "")
	project=req.path_info.split("/")[1] #drop preceeding / and directory
	user=req.user
	project.gsub!(/[\"\'\\^,;\/]/,"") #prevent sql injection (FIXME)
	user.gsub!(/[\"\'\\^,;\/]/,"") #prevent sql injection (FIXME)
	result = @dbh.select_one("select users.login,hashed_password,roles.name,root_url,users.salt,identifier,identifier IS NOT NULL from users left join members on members.user_id=users.id left join member_roles on member_roles.member_id=members.id left join projects on projects.id=members.project_id left join roles on roles.id=member_roles.role_id left join repositories on repositories.project_id=projects.id where identifier IS NOT NULL=1 AND roles.name=\"Developer\" AND (root_url LIKE \"http://redmine.scorec.rpi.edu/svn%#{project}\" OR root_url LIKE \"https://redmine.scorec.rpi.edu/svn%#{project}\") AND users.login=\"#{user}\"")
	#$stderr.puts "DB Result is:"
	#$stderr.puts result.inspect
	self.closedb
	return Apache::FORBIDDEN if result==nil 
	return Apache::FORBIDDEN if result[4]==nil #salt
	pass = Digest::SHA1.hexdigest(result[4]+pass || "")
	return Apache::FORBIDDEN if user==nil 
	return Apache::FORBIDDEN if pass==nil 
	return Apache::FORBIDDEN if project==nil 
	return Apache::FORBIDDEN if user!=result[0] 
	return Apache::FORBIDDEN if ((result[3].split("http://redmine.scorec.rpi.edu/svn/")[1] != project) && (result[3].split("https://redmine.scorec.rpi.edu/svn/")[1] != project))
	#$stderr.puts pass
	#$stderr.puts result[1]
	return Apache::FORBIDDEN if pass!=result[1] 
	return Apache::OK	
end

#Apache::FORBIDDEN
end


class Redminesvnanon

$disable_svn=:false
@dbuser="redmine"
@dbpass="PutPasswordHere"
@dbh
def initialize
@dbuser="redmine"
@dbpass="PutPasswordHere"
end

#access
def check_access(req)
return processreq(req)
	return Apache::FORBIDDEN if $disable_svn==:true
$stderr.puts "Ruby Access!"
$stderr.puts(req.remote_logname)
	$stderr.puts(req.get_basic_auth_pw)
	$stderr.puts(req.user)
	$stderr.puts(req.path_info)
return Apache::OK
end
#authen
def authenticate(req)
return processreq(req)
	return Apache::FORBIDDEN if $disable_svn==:true
$stderr.puts "authenticate"
	if req.user != "matthb2" then 
		return Apache::FORBIDDEN
	end
	$stderr.puts(req.get_basic_auth_pw)
	$stderr.puts(req.user)
	$stderr.puts(req.uri)
	$stderr.puts(req.filename)
	$stderr.puts(req.path_info)
	return Apache::OK
end
#authz
def authorize(req)
return processreq(req)
	return Apache::FORBIDDEN if $disable_svn==:true
$stderr.puts "authorize"
$stderr.puts(req.remote_logname)
	return Apache::OK
end

def opendb
@dbh=DBI.connect("DBI:Mysql:redmine:localhost",@dbuser,@dbpass)
end
def closedb
@dbh.disconnect if @dbh
end
def processreq(req)
r=processreq_helper(req)
$stderr.puts r.inspect
return r
end
def processreq_helper(req)
	$stderr.puts "Anon"
	$stderr.puts req.remote_host
	$stderr.puts req.hostname
	if req.remote_host == req.hostname.split(".")[0] then
		return Apache::OK #let the repo viewer work
	end
	self.opendb
	project=req.path_info.split("/")[1] #drop preceeding / and directory
	$stderr.puts "DBG:: project=#{project}"

	project.gsub!(/[\"\'\\^,;\/]/,"") #prevent sql injection (FIXME)
	result = @dbh.select_one("select value,projects.name from custom_values left join custom_fields on custom_fields.id=custom_values.custom_field_id left join projects on custom_values.customized_id=projects.id where custom_fields.name=\"AnonSVN\" AND custom_values.customized_type=\"Project\" AND projects.name=\"#{project}\"")
	self.closedb
	$stderr.puts result.inspect
	return Apache::FORBIDDEN if result == nil
	return Apache::FORBIDDEN if result[1].downcase != project.downcase #sanity check
	return Apache::FORBIDDEN if result[0].to_i != 1 
	return Apache::OK	
end

#Apache::FORBIDDEN
end
