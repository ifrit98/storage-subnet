# Migrate Redis to new Server

In the *origin* server we have to create a dump of the database. We can do it as follows:
```bash
# server: origin
A$ redis-cli
127.0.0.1:6379> CONFIG GET dir
1) "dir"
2) "/var/lib/redis/"
127.0.0.1:6379> SAVE
OK
```

In the *destiny* server we have to incorporate that data. We can do it as follows:
```bash
# server: destiny
sudo service redis-server stop
sudo cp /tmp/dump.rdb /var/lib/redis/dump.rdb
sudo chown redis: /var/lib/redis/dump.rdb
sudo service redis-server start
```

## References

- https://stackoverflow.com/questions/6004915/how-do-i-move-a-redis-database-from-one-server-to-another