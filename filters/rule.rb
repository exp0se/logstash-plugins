# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"
#
# This filter will add Suricata rules that matched a particular event
# as additional field.
# 
#
# The filter could be repurposed for simple data enrichment
# because it basicaly read files from directory then tries to find
# a match in particular field from event and then tries to match 
# that field to lines for files. If it finds a match it will add a
# matching line as a new field.    
# The config looks like this:
#
#     rule {
#         dir => "/etc/suricata/*.rules" 
#       }
#     }
# dir option take a directory path of files and optionally a extenstion mask
# for files you want to match against
# It works only with text files and do line by line matches
# 
# Contact info <takedownz@gmail.com>
class LogStash::Filters::Rule < LogStash::Filters::Base

  config_name "rule"
  milestone 1

  # The directory with files.
  config :dir, :validate => :string, :required => true

  public
  def register
    return @logger.warn("Directory #{@dir} doesn't exits") unless Dir.exists?(@dir.split('*')[0])
    @logger.debug("Loading Suricata rules from", :dir => @dir)
  end # def register

  public
  def filter(event)
    return unless filter?(event)
	# Check your Kibana scheme if your trying to find a field to match
	# nested field matched with ["level1[level2]"] syntax
	# e.g. alert.signature in Kibana panel become ["alert[signature]"] 
	sig = event["alert[signature]"]
	matched = ""
        Dir.glob(@dir) do |file| 
                rules = File.readlines(file)
                        rules.each do |rule|
                                matched = rule if rule.include?(sig) unless sig.nil? || sig.empty?
                        end
        end
	# Add a new field alert.signature_rule
	# This is tied to Suricata EVE JSON scheme
        event["alert[signature_rule]"] = matched unless matched.empty? || matched.nil?
	@logger.debug("Matched #{matched} with sig #{@sig}")
	filter_matched(event)
  end

end # class LogStash::Filters::Rule
