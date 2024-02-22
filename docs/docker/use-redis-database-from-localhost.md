# Use Redis Database from localhost

This process is similar to [migrate redis to new server](../redis/migrate-to-new-server.md). But in this case it all happens within the same host machine.

## Creating, run and stop redis container once

**Assuming**, that this is the first time you are going to run the redis container.

We will start by the redis container.

- First, we are going to build the container:
    - `sudo docker compose --env-file common.env --env-file filetao-validator.env up --build redis -d`
- Then, we are going to stop it:
    - `sudo docker compose --env-file common.env --env-file filetao-validator.env down redis`

### Why have we done this?
We have created, run and stop the container to force the creation of the volume and have locally what we have in the redis container aswell (we expect to see just the `appendonlydir` directory).

## Creating Redis local backup and move it to the Redis container

In this section, we **assume** that you have the default docker setup and you are using `/var/lib/docker` as your docker root directory. If this is not the case, ensure you use the corresponding command, with the correct docker root directory.

In the *host* server we have to create a dump of the database. We can do it as follows:
```bash
# server: origin
A$ redis-cli
127.0.0.1:6379> auth <your-passwd>
127.0.0.1:6379> CONFIG GET dir
1) "dir"
2) "/var/lib/redis/"
127.0.0.1:6379> SAVE
OK
A$ mv /var/lib/redis/dump.rdb /var/lib/docker/volumes/filetao-redis-data/_data/
```

In the *destiny* server we have to incorporate that data. We can do it as follows:
```bash
# server: origin
sudo docker compose --env-file common.env --env-file filetao-validator.env down redis
sudo docker compose --env-file common.env --env-file filetao-validator.env up --build redis -d
```

Now the redis container will receive the backup that we have just created and it is supposed to automatically get the new data.
