## Build and run

```sh
INIGO_STORAGE_URL=http://192.168.49.2:30020/query cargo run -- -s schema.graphql -c router.yaml
```

## Run Docker

You can use a ready-made public docker image:

```sh
docker run -it --rm -v $(pwd)/examples/middleware:/scheme/inigo -e APOLLO_ROUTER_SUPERGRAPH_PATH=/scheme/inigo/schema.graphql -e APOLLO_ROUTER_CONFIG_PATH=/scheme/inigo/router.yaml -p 4000:4000 -p 8088:8088 inigohub/inigo_apollo_router:latest
```

Then navigate to http://localhost:4000
