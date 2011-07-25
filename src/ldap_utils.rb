
require 'rubygems'
require 'utils'
require 'net/ldap'
require 'pp'


class LdapConnection 

  def initialize()
    @ldapconf = $config['LDAPInfo']
  end

  def initialize_ldap_con(ldap_user, ldap_password)
    options = { :host => @ldapconf['Host'] }
    options.merge!(:encryption => :simple_tls, :port => 636 ) if @ldapconf['SSL']
    options.merge!(:auth => { :method => :simple, :username => ldap_user, :password => ldap_password }) unless ldap_user.empty? && ldap_password.empty?
    Net::LDAP.new options
  end

  def authenticate(login, password)
    attrs = get_user_dn(login)
    if attrs && attrs[:dn] && authenticate_dn(attrs[:dn], password)
      return true
    else
      return false
    end
  rescue  Net::LDAP::LdapError => text
    raise "LdapError: " + text
  end

  def authenticate_dn(dn, password)
    initialize_ldap_con(dn, password).bind unless dn.empty? && ldap_password.empty?
  end

  def get_user_dn(login)
    user = login.strip.downcase
    ldap_con = initialize_ldap_con('','')
    login_filter = Net::LDAP::Filter.eq( "uid", user ) 
    object_filter = Net::LDAP::Filter.eq( "objectClass", "shadowaccount" ) 
    attrs = {}
    ldap_con.search( :base => @ldapconf['PeopleOU'], 
                     :filter => object_filter & login_filter, 
                     :attributes=> ['dn']) do |entry|
        attrs = {:dn => entry.dn}
    end
    return attrs
  end

  def getUserEntry(login)
    user = login.strip.downcase
    ldap_con = initialize_ldap_con('','')
    login_filter = Net::LDAP::Filter.eq( "uid", user ) 
    object_filter = Net::LDAP::Filter.eq( "objectClass", "shadowaccount" ) 
    attrs = {}
    entries = ldap_con.search( :base => @ldapconf['PeopleOU'], :filter => object_filter & login_filter ) 
    if entries.length == 0
      raise StandardError, "ERROR: no such user"
      return nil
    else 
      return entries[0]
    end
  end

  def update(user, password, options)
    dn = get_user_dn(user)[:dn]
    begin
      ldap_con = initialize_ldap_con(dn,password)
      options.each do | k , v|
        val = v[0]
        val = '' if val == nil
        ldap_con.replace_attribute(dn.to_s,k.to_s.strip,val.to_s.strip)
      end
    rescue StandardError => boom
      raise boom, caller
    rescue  Net::LDAP::LdapError => text
      raise "LdapError: " + text, caller
    end
    return true
  end
end

def password_check( yamls )
  # Check to see if it's defined in an ENV var
  password = ""
  if ENV['LDAP_PASSWORD']
    password = ENV['LDAP_PASSWORD']
  else
    password = yamls['LDAPInfo']['BindPW']
  end
  return password
end
