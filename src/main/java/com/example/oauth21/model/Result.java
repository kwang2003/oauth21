package com.example.oauth21.model;

import lombok.Data;

/**
 * 执行结果对象封装
 * @author kevin
 */
@Data
public class Result {
    private String code;
    private boolean success;
    private String message;
    private Object data;

    /**
     * 返回成功的执行结果对象
     * @return
     */
    public static Result success(){
        Result result = new Result();
        result.setSuccess(true);
        return result;
    }
    /**
     * 返回成功的执行结果对象
     * @param data 数据
     * @return
     */
    public static Result success(Object data){
        Result result = new Result();
        result.setSuccess(true);
        result.setData(data);
        return result;
    }

    /**
     * 返回失败的执行结果对象
     * @return
     */
    public static Result fail(){
        Result result = new Result();
        result.setSuccess(false);
        return result;
    }
    /**
     * 返回失败的执行结果对象
     * @param message 错误消息
     * @return
     */
    public static Result fail(String message){
        Result result = new Result();
        result.setSuccess(false);
        result.setMessage(message);
        return result;
    }
}
