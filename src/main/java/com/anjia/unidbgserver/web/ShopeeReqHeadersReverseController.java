package com.anjia.unidbgserver.web;

import com.alibaba.fastjson.JSONObject;
import com.anjia.unidbgserver.service.ShopeeSGAfAcEncServiceWorker;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;

import javax.annotation.Resource;

@Slf4j
@RestController
@RequestMapping(path = "/api/shopee", produces = MediaType.APPLICATION_JSON_VALUE)
public class ShopeeReqHeadersReverseController {

    @Resource(name = "ShopeeSGAfAcEncServiceWorker")
    private ShopeeSGAfAcEncServiceWorker shopeeSGAfAcEncServiceWorker;

    @SneakyThrows
    @RequestMapping(value = "afAcEncDat", method = {RequestMethod.GET})
    public String afAcEncDat() {
        String afAcEncDatStr = shopeeSGAfAcEncServiceWorker.ShopeeSGAfAcEncDat().get();
        log.info("af-ac-enc-dat: {}", afAcEncDatStr);
        return afAcEncDatStr;
    }

    /**
     * 调用 public static native int vuwuuwvu(wvvvuvvv wvvvuvvvVar);
     * 该方法需要传入两个参数，根据第一个不同的参数，会走不同的代码流程。
     * 根据 reqParamName 进行区分，比如要获取 af-ac-enc-id 值，reqParamName 就设置为 afAcEncId
     * 获取 af-ac-enc-sz-token 值的参数时，发起的请求里的 riskToken 值，reqParamName 则设置为 afAcEncSzToken
     *
     * @param reqParams
     * @return
     */
    @SneakyThrows
    @RequestMapping(value = "otherReqParam/{callReqParamName}", method = {RequestMethod.POST})
    public String callWvvvuvvvVuwuuwvu(@PathVariable(name = "callReqParamName") String reqParamName,
                                       @RequestBody JSONObject reqParams) {
        int wvvvuwuw = reqParams.getInteger("wvvvuwuw");
        String wvvvuwuu = reqParams.getString("wvvvuwuu");
        log.info("request param: {}", reqParamName);
        log.info("req params wvvvuwuw: {}", wvvvuwuw);
        log.info("req params wvvvuwuu: {}", wvvvuwuu);

        String otherReqParamStr = shopeeSGAfAcEncServiceWorker.callWvvvuvvvVuwuuwvu(reqParamName, wvvvuwuw, wvvvuwuu).get();
        if (reqParamName.equals("afAcEncId")) {
            log.info("af-ac-enc-id: {}", otherReqParamStr);
        } else if (reqParamName.equals("afAcEncSzToken")) {
            log.info("af-ac-enc-sz-token: {}", otherReqParamStr);
        }
        return otherReqParamStr;
    }
}
