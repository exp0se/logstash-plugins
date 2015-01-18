#!/bin/bash
echo "What gem do you want?"
read gem
echo "Will now install $gem in logstash JRuby"
cd /opt/logstash
env GEM_HOME=vendor/bundle/jruby/1.9 GEM_PATH="" java -jar vendor/jar/jruby-complete-1.7.11.jar -S gem install $gem
