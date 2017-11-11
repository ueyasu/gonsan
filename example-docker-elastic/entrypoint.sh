#! /bin/sh
tail -f /gonsan/logstash.txt | logstash -e '
input { stdin {codec => json} } 
output { elasticsearch 
  {
     hosts => ["http://elasticsearch:9200"] 
     template => "/gonsan/template.json"
     index => "gonsan-%{+YYYY.MM.DD}"
  }
}'

