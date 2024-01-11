package com.example.oauth21.authentication.sms;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;

import java.util.concurrent.TimeUnit;

/**
 * @author kevin
 */
@Component
public class RedisTokenBucket {
    private static final long EXPIRE_TIME = 400;
    @Autowired
    private StringRedisTemplate stringRedisTemplate;

    /**
     * 令牌桶算法，一分钟以内，每个手机号只能发送一次
     * @param phoneNumber 手机号
     * @return
     */
    public boolean tryAcquire(String phoneNumber){
        Assert.hasText(phoneNumber,"手机号不能为空");
        //每个手机号一分钟内只能发送一条短信
        int permitsPerMinute = 1;
        //令牌桶容量
        int maxPermits = 1;
        long now = System.currentTimeMillis();
        String key = RedisSmsConstant.SMS_BUCKET_PREFIX +phoneNumber;
        //计算令牌桶内令牌数
        String existToken = stringRedisTemplate.opsForValue().get(key+"_tokens");
        int tokens = Integer.parseInt(existToken== null?"0":existToken);
        //计算令牌桶上次填充时间戳
        String existLastFill = stringRedisTemplate.opsForValue().get(key+"_last_refill_time");
        long lastRefillTime = Long.parseLong(existLastFill == null ? "0":existLastFill);
        //计算本次与上次的时间差
        long timeSinceLast = now - lastRefillTime;
        //计算需要填充的令牌数
        int refill = (int) (timeSinceLast/1000*permitsPerMinute/60);
        // 更新令牌桶内令牌数
        tokens = Math.min(refill+tokens,maxPermits);
        //更新上次填充时间
        stringRedisTemplate.opsForValue().set(key+"_last_refill_time",String.valueOf(now),EXPIRE_TIME, TimeUnit.SECONDS);
        if(tokens >= 1){
            tokens--;
            stringRedisTemplate.opsForValue().set(key+"_tokens",String.valueOf(tokens),EXPIRE_TIME, TimeUnit.SECONDS);
            return true;
        }
        return false;
    }
}
