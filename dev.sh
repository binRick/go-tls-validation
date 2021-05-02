
cmd="./run.sh $@"
nodemon --delay .1 -w . -e go -x sh -- -c "$cmd||true"
