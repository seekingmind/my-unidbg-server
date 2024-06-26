package com.anjia.unidbgserver.web;

import com.anjia.unidbgserver.service.ShopeeSGAfAcEncServiceWorker;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

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

    @SneakyThrows
    @RequestMapping(value = "afAcEncId", method = {RequestMethod.GET})
    public String afAcEncId() {
        String afAcEncIdStr = shopeeSGAfAcEncServiceWorker.ShopeeSGAfAcEncId().get();
        log.info("af-ac-enc-id: {}", afAcEncIdStr);
        return afAcEncIdStr;
    }
}
