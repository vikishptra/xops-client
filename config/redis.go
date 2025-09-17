package config

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

var (
	RedisClient *redis.Client
	ctx         context.Context
)

func ConnectRedis(config *InitConfig) {
	ctx = context.TODO()

	RedisClient = redis.NewClient(&redis.Options{
		Addr:     config.RedisUri,
		Password: "s3ct0r-kyc",
		DB:       0,
	})
	// _, err := RedisClient.FlushDB(ctx).Result()
	// if err != nil {
	// 	fmt.Println("Gagal menghapus kunci dari basis data:", err.Error())
	// 	return
	// }
	if _, err := RedisClient.Ping(ctx).Result(); err != nil {
		panic(err)
	}

	// err := RedisClient.Set(ctx, "test", "test", 0).Err()
	// if err != nil {
	// 	panic(err)
	// }

	fmt.Println("✅ Redis client connected successfully...")
}

func GetFromCache(key string) ([]byte, error) {
	ctx := context.Background()
	result, err := RedisClient.Get(ctx, key).Bytes()
	if err != nil {
		return nil, err
	}
	return result, nil
}

func SetToCache(key string, value int64, expiration time.Duration) error {
	ctx := context.Background()
	jsonValue, err := json.Marshal(value)
	if err != nil {
		return err
	}
	err = RedisClient.Set(ctx, key, jsonValue, expiration).Err()
	if err != nil {
		return err
	}
	return nil
}
func SetToCacheRansomwareLive(key string, value []map[string]interface{}, expiration time.Duration) error {
	ctx := context.Background()
	jsonValue, err := json.Marshal(value)
	if err != nil {
		return err
	}
	err = RedisClient.Set(ctx, key, jsonValue, expiration).Err()
	if err != nil {
		return err
	}
	return nil
}
func SetToCacheRansomwareLiveNoArray(key string, value map[string]interface{}, expiration time.Duration) error {
	ctx := context.Background()
	jsonValue, err := json.Marshal(value)
	if err != nil {
		return err
	}
	err = RedisClient.Set(ctx, key, jsonValue, expiration).Err()
	if err != nil {
		return err
	}
	return nil
}
func SetToCacheInterface(key string, value interface{}, expiration time.Duration) error {
	ctx := context.Background()
	jsonValue, err := json.Marshal(value)
	if err != nil {
		return err
	}
	err = RedisClient.Set(ctx, key, jsonValue, expiration).Err()
	if err != nil {
		return err
	}
	return nil
}

func SetToCacheAsync(key string, value interface{}, expiration time.Duration) {
	go func() {
		err := SetToCacheInterface(key, value, expiration)
		if err != nil {
			fmt.Println("Error caching data:", err)
		}
	}()
}

func BuildCacheKey(params ...string) string {
	return fmt.Sprintf("api:%s", strings.Join(params, ":"))
}
func UpdateCache(data, key string, value int64, expiration time.Duration) error {

	if err := DeleteKeysWithPattern(fmt.Sprintf("%s %s*", data, key)); err != nil {
		return err
	}
	dataKey := data + key
	if err := SetToCache(dataKey, value, expiration); err != nil {
		return err

	}

	return nil
}

func DeleteKeysWithPattern(pattern string) error {
	ctx := context.Background()
	keys, err := RedisClient.Keys(ctx, pattern).Result()
	if err != nil {
		return err
	}
	if len(keys) > 0 {
		if err := RedisClient.Del(ctx, keys...).Err(); err != nil {
			return err
		}
	}

	return nil
}
func LoopDeleteKeysByPattern(pattern string) error {
	var cursor uint64
	for {
		keys, nextCursor, err := RedisClient.Scan(ctx, cursor, pattern, 0).Result()
		if err != nil {
			return fmt.Errorf("failed to scan keys: %v", err)
		}

		for _, key := range keys {
			_, err := RedisClient.Del(ctx, key).Result()
			if err != nil {
				return fmt.Errorf("failed to delete key %s: %v", key, err)
			}
		}

		if nextCursor == 0 {
			break
		}
		cursor = nextCursor
	}
	return nil
}
func GetFromCacheArray(pattern string) (int, error) {
	ctx := context.Background()

	keys, err := RedisClient.Keys(ctx, pattern).Result()
	if err != nil {
		return 0, fmt.Errorf("error saat mengambil keys dari Redis: %w", err)
	}

	// Jika tidak ada key yang ditemukan
	if len(keys) == 0 {
		return 0, fmt.Errorf("key tidak ditemukan dengan pola: %s", pattern)
	}

	total := 0
	for _, key := range keys {
		// Ambil value dari Redis
		valueStr, err := RedisClient.Get(ctx, key).Result()
		if err != nil {
			return 0, fmt.Errorf("error saat mengambil data dari Redis untuk key %s: %w", key, err)
		}

		valueInt, err := strconv.Atoi(valueStr)
		if err != nil {
			return 0, fmt.Errorf("error saat mengonversi value ke int untuk key %s: %w", key, err)
		}

		total += valueInt
	}

	return total, nil
}
