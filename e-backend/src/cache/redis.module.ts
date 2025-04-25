import { Module, Logger } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { CacheModule } from '@nestjs/cache-manager';
import * as redisStore from 'cache-manager-redis-store';

@Module({
  imports: [
    CacheModule.registerAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: async (configService: ConfigService) => {
        const logger = new Logger('RedisModule');
        const host = configService.get('REDIS_HOST', 'localhost');
        const port = configService.get('REDIS_PORT', 6379);
        
        logger.log(`Connecting to Redis at ${host}:${port}`);
        
        return {
          store: redisStore,
          host,
          port,
          ttl: 300, // TTL for OTP - 5 minutes (in seconds)
          max: 50, // maximum number of items in cache
          isGlobal: true,
        };
      },
      isGlobal: true,
    }),
  ],
  exports: [CacheModule],
})
export class RedisModule {}