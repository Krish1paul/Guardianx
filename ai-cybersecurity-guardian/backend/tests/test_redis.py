"""Tests for Redis abstraction and client management — M5 Production Hardening."""

from __future__ import annotations

import time
from unittest.mock import MagicMock

from app.core.redis import (
    InMemoryRedisClient,
    RedisClient,
    get_redis_client,
    reset_redis_client,
)


class TestInMemoryRedisClient:
    def test_ping(self) -> None:
        client = InMemoryRedisClient()
        assert client.ping() is True

    def test_get_set_delete_exists(self) -> None:
        client = InMemoryRedisClient()
        assert client.get("foo") is None
        assert client.exists("foo") == 0

        assert client.set("foo", "bar") is True
        assert client.get("foo") == "bar"
        assert client.exists("foo") == 1

        assert client.delete("foo") == 1
        assert client.get("foo") is None
        assert client.exists("foo") == 0
        assert client.delete("foo") == 0

    def test_expiration(self) -> None:
        client = InMemoryRedisClient()
        client.set("temp", "val", ex=1)
        assert client.get("temp") == "val"
        assert client.exists("temp") == 1

        # Simulate expiration
        client._expires["temp"] = time.monotonic() - 1
        assert client.get("temp") is None
        assert client.exists("temp") == 0

    def test_expire_command(self) -> None:
        client = InMemoryRedisClient()
        assert client.expire("nonexistent", 60) is False
        client.set("key", "val")
        assert client.expire("key", 60) is True
        assert "key" in client._expires

    def test_zset_operations(self) -> None:
        client = InMemoryRedisClient()
        assert client.zcard("zkey") == 0

        # Add items
        added = client.zadd("zkey", {"item1": 100.0, "item2": 200.0, "item3": 300.0})
        assert added == 3
        assert client.zcard("zkey") == 3

        # Update item
        updated = client.zadd("zkey", {"item1": 150.0})
        assert updated == 0
        assert client.zcard("zkey") == 3

        # Remove by score range
        removed = client.zremrangebyscore("zkey", "-inf", "150.0")
        assert removed == 1
        assert client.zcard("zkey") == 2

        removed_all = client.zremrangebyscore("zkey", "-inf", "+inf")
        assert removed_all == 2
        assert client.zcard("zkey") == 0

    def test_clear_and_close(self) -> None:
        client = InMemoryRedisClient()
        client.set("a", "1")
        client.zadd("z", {"m": 1.0})
        assert client.exists("a", "z") == 2
        client.clear()
        assert client.exists("a", "z") == 0
        client.close()


class TestRedisClientWrapper:
    def test_ping_success_and_failure(self) -> None:
        wrapper = RedisClient("redis://localhost:6379/0")
        mock_redis = MagicMock()
        mock_redis.ping.return_value = True
        wrapper._client = mock_redis
        assert wrapper.ping() is True

        mock_redis.ping.side_effect = Exception("Connection refused")
        assert wrapper.ping() is False

    def test_commands_delegation(self) -> None:
        wrapper = RedisClient("redis://localhost:6379/0")
        mock_redis = MagicMock()
        mock_redis.get.return_value = "hello"
        mock_redis.set.return_value = True
        mock_redis.delete.return_value = 1
        mock_redis.exists.return_value = 1
        mock_redis.expire.return_value = True
        mock_redis.zadd.return_value = 2
        mock_redis.zremrangebyscore.return_value = 1
        mock_redis.zcard.return_value = 5
        wrapper._client = mock_redis

        assert wrapper.get("k") == "hello"
        assert wrapper.set("k", "v", ex=10) is True
        assert wrapper.delete("k") == 1
        assert wrapper.exists("k") == 1
        assert wrapper.expire("k", 30) is True
        assert wrapper.zadd("zk", {"m": 1.0}) == 2
        assert wrapper.zremrangebyscore("zk", 0, 10) == 1
        assert wrapper.zcard("zk") == 5


class TestRedisSingleton:
    def test_get_and_reset_singleton(self) -> None:
        reset_redis_client()
        client1 = get_redis_client()
        client2 = get_redis_client()
        assert client1 is client2

        custom = InMemoryRedisClient()
        reset_redis_client(custom)
        assert get_redis_client() is custom
        reset_redis_client()
