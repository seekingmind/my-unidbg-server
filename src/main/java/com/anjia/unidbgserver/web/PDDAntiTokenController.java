package com.anjia.unidbgserver.web;

import com.anjia.unidbgserver.service.PDDAntiTokenServiceWorker;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import javax.annotation.Resource;

@Slf4j
@RestController
@RequestMapping(path = "/api/pdd", produces = MediaType.APPLICATION_JSON_VALUE)
public class PDDAntiTokenController {

    @Resource(name = "PDDAntiTokenServiceWorker")
    private PDDAntiTokenServiceWorker pddAntiTokenServiceWorker;

    @SneakyThrows
    @RequestMapping(value = "antiToken", method = {RequestMethod.GET})
    public String ttEncrypt() {
        String result = pddAntiTokenServiceWorker.PDDAntiToken().get();
        log.info("anti_token: {}", result);
        return result;
    }
}
