#!/usr/bin/env ruby
#
require 'net/smtp'
require 'erb'
require 'utils'
require 'presentation'

def sendmail(from, to, subject, message, options = {}) 
  #   => from_alias (optional)
  #   =>  to_alias (optional)       
  from = options[:from_alias].to_s  + "<#{from}>"
  to = options[:to_alias].to_s  + "<#{to}>"
  msg = <<EOF
From: #{from}
To: #{to}
Subject: #{subject}

#{message}
EOF
  Net::SMTP.start('localhost') do |smtp|
    smtp.send_message( msg, from, to  ) 
  end
end


#sendmail('mike@whatever.com', 'mastahnke@gmail.com', 'whatever', 'message body' , { :from_alias => 'mikealias' , :to_alias => "Yo"}  ) 
#
# Use Erb for email probably
# "You, or somebody claiming to be you has forgotten your password on #{site}.  To reset your password please use the following link which is valid for the next #{time} hours.  
#   #{session_ur}.  
#If you miraculously remember your password, or decide not to reset anything, your old password will still work. 
#
#Thank you,
#{site} Admins
#
#
#"
#
def resetMail(to)
  #  Get from , from_alias, from YAML
  config = loadConfig('../configuration.yaml')
  options = {}
  options[:from] =  config['PWReset']['FromAddress']
  options[:from_alias] = config['PWReset']['FromAlias']
  options[:site] = config['Site']
  options[:time] = config['PWReset']['Timeout']
  options[:subject] = "Password Reset Request from '#{options[:site]}.'"
  options[:to] = to
  options[:session_uri] = 'http://example.com/reset/52ffa5d718d3fcb210df9ee5f57e79e94b18532a6363e0b0f531db9fa53053c4'
  options[:message] = content(config, 'password_reset_mail.erb', options)
  sendmail(options[:from], options[:to],  options[:subject], options[:message], options)
end


#resetMail('mike')