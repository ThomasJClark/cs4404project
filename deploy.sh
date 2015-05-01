#!/bin/bash

go install ./aitf-client ./aitf-router
scp $GOPATH/bin/aitf-client* root@10.4.32.1:/root/
scp $GOPATH/bin/aitf-router* root@10.4.32.2:/root/
scp $GOPATH/bin/aitf-router* root@10.4.32.3:/root/
scp $GOPATH/bin/aitf-client* root@10.4.32.4:/root/

