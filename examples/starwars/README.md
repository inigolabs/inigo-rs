## Build and run

- Start
```sh
    export INIGO_SERVICE_TOKEN="..." # Get from app.inigo.io
    cargo run
```

- Open your browser to [http://localhost:4000](http://localhost:4000) to interact with your app.

- Run the following example graphql query to get started:
```graphql
query {
  hero(episode:NEW_HOPE) {
    name
    friends {
      name
      appearsIn
      id
    }
  }
}
```

- Expected response:
```json
{
  "data": {
    "hero": {
      "name": "R2-D2",
      "friends": [
        {
          "name": "Luke Skywalker",
          "appearsIn": [],
          "id": "1000"
        },
        {
          "name": "Han Solo",
          "appearsIn": [
            "EMPIRE",
            "NEW_HOPE",
            "JEDI"
          ],
          "id": "1002"
        },
        {
          "name": "Leia Organa",
          "appearsIn": [
            "EMPIRE",
            "NEW_HOPE",
            "JEDI"
          ],
          "id": "1003"
        }
      ]
    }
  },
  "extensions": {
    "inigo": {
      "status": "PASSED",
      "trace_id": "e56d1b36-3758-4381-838c-ed79a9675a9e"
    }
  }
}
```