
require 'erb'
require 'ldap_utils'
require 'utils'
require 'cgi'
require 'cgi/session'
require 'password'

def activeSession()
  return !($session['login'].nil?)
end

def renderEngine(options)
   findFields(options)
end

def logout(cgi)
  begin
    $session['login'] = nil
    $session['password'] = nil
    $session.close
    $session.delete
  rescue 
    # nothing? 
  end  
  print cgi.header({'Status' => '302 Moved', 'location' =>  '/'})
  return
end


def login(login, password)
  l = LdapConnection.new()
  bindstat = l.authenticate(login, password)
  if bindstat == true
    return true
  else
    $session.close
    $session.delete
    raise StandardError, "ERROR: Invalid credentials"
    return false
  end
end

def manageUser(options = {})
   options[:write_fields] = {}
   $config['UserWritableAttrs'].each do |k, v|
     options[:write_fields][k] = v 
   end
   options[:read_fields] = {}
   $config['ReadOnlyAttrs'].each do |k, v|
     options[:read_fields][k] = v 
   end
   options[:entry] = retrInfo()
   return options
end 

def updateLdap(options = {} )
  options.delete('action')
  options.each do | k , v|
    if v.to_s.size.to_i < 1
      options[k] = [ ]
    end
  end
  pw = options['userPassword']
  if pw.empty?
    options.delete('userPassword')
    options.delete('confirmPassword')
  elsif ! (pw == options['confirmPassword'])
    raise StandardError, "Passwords do not match."
    return  false
  else
    options.delete('confirmPassword')
  end
  
  l = LdapConnection.new
  result = l.update($session['login'].to_s, $session['password'].to_s, options)
  if options['userPassword'].to_s.length > 1
       $session['password'] =  options['userPassword'].to_s
       l = nil
       sleep 2
       l = LdapConnection.new
       $session['ldap'] = l.authenticate($session['login'].to_s, $session['password'].to_s)
  end
  return result
end


def retrInfo()
  l = LdapConnection.new
#  l.authenticate($session['login'].to_s, $session['password'].to_s)
  entry = l.getUserEntry($session['login'].to_s)
end

def adminBind()
  l  = LdapConnection.new
#  pp config
#  TODO generate a an error if this bind can't happen
  begin
    l.login($config['LDAPInfo']['BindDN'], $config['LDAPInfo']['BindPW'])
  rescue LDAP::ResultError => boom
    raise LDAP::ResultError, boom.to_s, caller
  end
  return l
end

def emailOrLogin(login)
  if login.chomp.to_s.length < 1
     return false
  end

  if login =~ /@/
    return 'mail'
  else
    return 'uid'
  end
end

def lookupEmail(value, field)
  l = adminBind 
  if field == 'mail'
    begin
      entry = l.getEntryByMail(value)
    rescue LDAP::ResultError => boom
      raise LDAP::ResultError, boom.to_s, caller
    end
  elsif field == 'uid'
    begin
      entry = l.getUserEntry(value)
    rescue LDAP::ResultError => boom
      raise LDAP::ResultError, boom.to_s, caller
    end
  end
  begin 
    return entry['mailDrop'][0] 
  rescue 
    raise LDAP::ResultError, "Unable to find email address in directory.  Contact support directly.", caller
  end
end

def lookupUID(value, field)
  l = adminBind
  if field == 'mail'
    begin
      entry = l.getEntryByMail(value)
    rescue LDAP::ResultError => boom
      raise LDAP::ResultError, boom.to_s, caller
    end
  elsif field == 'uid'
    begin
      entry = l.getUserEntry(value)
    rescue LDAP::ResultError => boom
      raise LDAP::ResultError, boom.to_s, caller
    end
  end
  return entry['uid'][0]
end


def adminUpdate(login, options)
  l = adminBind
  options.delete('confirmPassword')
  l.update(login, options)
end
