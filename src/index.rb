#!/usr/bin/ruby

require 'rubygems'
require 'utils'
require 'ldap_utils'
require 'generate_login'
require 'presentation'
require 'pp'
require 'cgi'
require 'cgi/session'
require 'mail'
require 'password'
require 'logger'

$config = loadConfig('../config/config.yaml')
#$log = Logger.new("../log/debug.log")

stream = ""
cgi = CGI.new("html4")
options = {}

begin
  $session = CGI::Session.new(cgi, :database_manager => CGI::Session::MemoryStore,
                                   :session_expires => Time.now + $config['PWReset']['Timeout'] * 60 * 60,
                                   :session_id => cgi.params['_session_id'].to_int,
                                   :new_session => false )
rescue
  $session = CGI::Session.new(cgi, :database_manager => CGI::Session::MemoryStore,
                                   :session_expires => Time.now + $config['PWReset']['Timeout'] * 60 * 60,
                                   :new_session => true )
end
$session['login'] = cgi['login'].to_s if cgi.has_key?('login')
$session['password'] = cgi['password'].to_s if cgi.has_key?('password')

def streamLogin(cgi)
  stream = " "
  options = {}
  uid = cgi['login'].to_s
  password = cgi['password'].to_s
  login(uid, password)
  return stream.to_s
end

def selfManage(cgi)
  stream = ""
  options = manageUser()
  stream += renderfarm('manage.erb', options)
  return stream
end

def selfChange(cgi)
  stream = ""
  updateLdap(cgi.params)
  options = manageUser()
  options[:notice] = "Account Updated Sucessfully."
  stream += renderfarm('manage.erb', options)
  return stream
end

case cgi.params['action'].to_s
  when 'logout'
    logout(cgi)
  when 'login'
    begin
      stream += streamLogin(cgi)
    rescue StandardError => boom
       options[:errors]  =  boom
       options[:forgot_link] = "/?action=forgot"
       stream += renderfarm('login.erb', options)
       cgi.html{
         cgi.out{ stream } 
       }
       exit
    end
    stream += selfManage(cgi) if activeSession() and $session['password']
  when 'change'
    begin
      stream += selfChange(cgi) if activeSession() and $session['password']
    rescue StandardError => boom
       options[:errors]  =  boom
       options[:forgot_link] = "/?action=forgot"
       stream += renderfarm('login.erb', options)
    end
  when 'forgot'
    if cgi.params['step'].to_s == 'validate'
       unless cgi.params['login'].to_s.empty?
         type = emailOrLogin(cgi.params['login'].to_s) 
         begin
           email_address = lookupEmail(cgi.params['login'].to_s, type)
           options[:session_id] = $session.session_id 
           $session['email'] = email_address
           $session['login'] = lookupUID(cgi.params['login'].to_s, type)
           options[:uri] = ENV['HTTP_REFERER'] + "&step=reset&_session_id=" + options[:session_id]
           resetMail(email_address, options)
           options[:notice] = "Verification email sent."
         rescue RuntimeError  => boom
           options[:errors] = boom.to_s
         end
       else
          options[:errors] = "You need to enter something."
       end
       options[:login_link] = "/password"
       stream += renderfarm('forgot.erb', options)
    elsif cgi.params['step'].to_s == 'reset'
       options[:login] = $session['login']
       stream += renderfarm('password_reset.erb', options)
    elsif cgi.params['step'].to_s == 'adminreset'
       # Validate a password was Entered (assigned as arrays)
       password = { 'userPassword' => cgi.params['userPassword'], 
                    'confirmPassword' => cgi.params['confirmPassword'] }
       options[:login] = $session['login']
       pw = PW.new(password['userPassword'].to_s)
       if ! pw.empty? and (pw == password['confirmPassword'].to_s)
           begin
             adminUpdate($session['login'] , password)
             options[:notice] = "Account Updated Sucessfully."
             # Logout hack here
             $session.close
             $session.delete
           rescue 
             options[:errors] = "ZOMG"
           end
           # probably logout here
           stream += renderfarm('password_reset.erb', options)
       else
           options[:errors] = "Passwords do not match."
           stream += renderfarm('password_reset.erb', options)
       end
    else 
       options[:login_link] = "/password"
       stream += renderfarm('forgot.erb', options)
    end
  else
    options[:forgot_link] = "/?action=forgot"
    stream += renderfarm('login.erb', options)
end 

cgi.html{
  cgi.out{ stream } 
}
