## Deploying a Fake Server to KNE

```bash
# The name is temporary and will be changed once the image is registered.
docker build -t wenovus/fakeserver0 -f Dockerfile GOPATH/src/github.com
kind load docker-image wenovus/fakeserver0 --name kne
```

## Running the Integration Test

```bash
go test -v=1 -alsologtostderr -testbed=testbed.textproto -config ../kne_example/kne_config.yaml
```

A KNE config YAML file is needed to run the integration test.

#### Sample templated YAML file

```yaml
username: foo
password: bar
topology: <$GOPATH>/src/github.com/wenovus/ondatra/fakebind/kne_example/2node-fake.textproto
cli: <$GOPATH>/bin/kne_cli
kubecfg: <$HOME>/.kube/config
```
