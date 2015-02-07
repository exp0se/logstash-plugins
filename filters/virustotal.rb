# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"
#
# This filter will check md5 hashes detected by Suricata against
# virustotal service and add results into additional field for events.
#
# This plugin make use of rest_client gem
# To install this gem into logstash JRuby use install_gem.sh script
# 
# The config looks like this:
#
# filter {
#  if [fileinfo] { #It's better to use filter only if fileinfo field is present
#       virustotal {
#         apikey => "1fe0ef5feca2f84eb450bc3617f839e317b2a686af4d651a9bada77a522201b0" 
#         interesting_files => [ "PE32", "Java", "PDF", "Flash" ]
#	}
#     }
# }
# 
# apikey is option to provide your virustotal api key
# interesting_files is option to provide file magic types you are interested in
# to check against virustotal. This option is case sensitive
# This option relies on Suricata ability to detect magic types which in turn uses 
# Linux file command magic database
# So you need to provide a unique part of magic string to effectivly match files
# For example if you want to search only Windows EXE files on virustotal
# then you need to use "PE32" part of the string detected by file command because this part is present in all Windows executables 
# including Dos files and others however if you used "Windows" part this would work as well but not every
# executable would be matched  
# Contact info <takedownz@gmail.com>
class LogStash::Filters::Virustotal < LogStash::Filters::Base

  config_name "virustotal"
  milestone 1

  config :apikey, :validate => :string, :required => true
  config :interesting_files, :validate => :array, :required => true

  public
  def register
	require 'rest_client'
	require 'json'
      @logger.debug("Config options received", :apikey => @apikey, :interesting_files => @interesting_files)
  end
  public
  def filter(event)
    return unless filter?(event)
	# Check your Kibana fields if your trying to find a field to match
	# nested fields matched with ["level1[level2]"] syntax
	# e.g. alert.signature in Kibana panel become ["alert[signature]"]
	# 
	# We only interested in specific files and we quit unless we find any
	file_magic = event["fileinfo[magic]"]
	return @logger.debug("fileinfo magic is null or empty") if file_magic.nil? || file_magic.empty?
	return @logger.debug("Didnt find any interesting files, current magic #{file_magic}") unless @interesting_files.any? { |file| file_magic[file] }
	@logger.debug("Find magic #{file_magic}")
	url = 'https://www.virustotal.com/vtapi/v2/file/report'
	md5 = event["fileinfo[md5]"]
	return @logger.debug("md5 hash is empty") if md5.nil? || md5.empty?
	check_hash = RestClient.get "#{url}", :params => { :apikey => @apikey, :resource => "#{md5}" }
	begin
		results = JSON.parse(check_hash)
	rescue
		return @logger.debug("skipping json parsing exception")
	end
	# Add a new field virustotal with results
	# This is tied to Suricata EVE JSON scheme
        event["fileinfo[virustotal]"] = results unless results.empty? || results.nil? || results["response_code"] == 0 || results["response_code"] == -1
	@logger.debug("Results #{results}")
	filter_matched(event)
  end

end # class LogStash::Filters::Virustotal
