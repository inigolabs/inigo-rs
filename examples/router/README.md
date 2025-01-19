## Build and run

1. Download library artifact from `https://github.com/inigolabs/artifacts/releases`
2. Place it in the current directory.
3. Rename it to libinigo (.so, .dylib or .dll)

```sh
export INIGO_LIB_PATH=$(pwd)
export INIGO_SERVICE_TOKEN="..." # Get it from app.inigo.io
cargo run -- -s schema.graphql -c router.yaml
```
