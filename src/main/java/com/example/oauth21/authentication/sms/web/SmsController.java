package com.example.oauth21.authentication.sms.web;

import com.example.oauth21.authentication.sms.RedisSmsConstant;
import com.example.oauth21.authentication.sms.RedisTokenBucket;
import com.example.oauth21.model.Result;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.RandomStringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.concurrent.TimeUnit;

/**
 * 短信验证码web api
 * @author kevin
 */
@Slf4j
@RestController
@RequestMapping("/sms")
public class SmsController {
    @Autowired
    private RedisTokenBucket redisTokenBucket;
    @Autowired
    private StringRedisTemplate stringRedisTemplate;
    @GetMapping("/send")
    public Result send(@RequestParam(value = "mobile", required = true)String mobile){
        return sendSmsCode(mobile);
    }

    /**
     * 发送手机验证码
     * @param phoneNumber
     * @return
     */
    private Result sendSmsCode(String phoneNumber){
        boolean acquire = redisTokenBucket.tryAcquire(phoneNumber);
        if(!acquire){
            log.error("手机号:{}发送频繁！",phoneNumber);
            return Result.fail("发送过于频繁，请稍后再试！");
        }

        String code = RandomStringUtils.randomAlphanumeric(6);
        stringRedisTemplate.opsForValue().set(RedisSmsConstant.SMS_CODE_PREFIX+phoneNumber,code,5, TimeUnit.MINUTES);
        log.info("phone={},code={}",phoneNumber,code);
        //TODO 调用短信发送接口发送
        return Result.success();
    }
}
