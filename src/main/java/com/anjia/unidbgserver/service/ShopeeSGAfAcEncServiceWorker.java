package com.anjia.unidbgserver.service;

import com.anjia.unidbgserver.config.UnidbgProperties;
import com.github.unidbg.worker.Worker;
import com.github.unidbg.worker.WorkerPool;
import com.github.unidbg.worker.WorkerPoolFactory;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

@Slf4j
@Service("ShopeeSGAfAcEncServiceWorker")
public class ShopeeSGAfAcEncServiceWorker extends Worker {
    private UnidbgProperties unidbgProperties;
    private WorkerPool pool;
    private ShopeeSGAfAcEncService shopeeSGAfAcEncService;

    @Autowired
    public void init(UnidbgProperties unidbgProperties) {
        this.unidbgProperties = unidbgProperties;
    }

    public ShopeeSGAfAcEncServiceWorker(WorkerPool pool) {
        super(pool);
    }

    @Autowired
    public ShopeeSGAfAcEncServiceWorker(UnidbgProperties unidbgProperties, @Value("${spring.task.execution.pool.core-size:4}") int poolSize) {
        super(WorkerPoolFactory.create(ShopeeSGAfAcEncServiceWorker::new, Runtime.getRuntime().availableProcessors()));
        this.unidbgProperties = unidbgProperties;
        if (this.unidbgProperties.isAsync()) {
            pool = WorkerPoolFactory.create(pool -> new ShopeeSGAfAcEncServiceWorker(unidbgProperties.isDynarmic(), unidbgProperties.isVerbose(), pool), Math.max(poolSize, 4));
            log.info("线程池为:{}", Math.max(poolSize, 4));
        } else {
            this.shopeeSGAfAcEncService = new ShopeeSGAfAcEncService(unidbgProperties);
        }
    }

    public ShopeeSGAfAcEncServiceWorker(boolean dynarmic, boolean verbose, WorkerPool pool) {
        super(pool);
        this.unidbgProperties = new UnidbgProperties();
        unidbgProperties.setDynarmic(dynarmic);
        unidbgProperties.setVerbose(verbose);
        log.info("是否启用动态引擎:{},是否打印详细信息:{}", dynarmic, verbose);
        this.shopeeSGAfAcEncService = new ShopeeSGAfAcEncService(unidbgProperties);
    }

    @Async
    @SneakyThrows
    public CompletableFuture<String> ShopeeSGAfAcEncDat() {
        ShopeeSGAfAcEncServiceWorker worker;
        String result;
        if (this.unidbgProperties.isAsync()) {
            while (true) {
                if ((worker = pool.borrow(2, TimeUnit.SECONDS)) == null) {
                    continue;
                }
                result = worker.doAfAcEncDatWork();
                pool.release(worker);
                break;
            }
        } else {
            synchronized (this) {
                result = this.doAfAcEncDatWork();
            }
        }

        return CompletableFuture.completedFuture(result);
    }

    @Async
    @SneakyThrows
    public CompletableFuture<String> ShopeeSGAfAcEncId() {
        ShopeeSGAfAcEncServiceWorker worker;
        String result;
        if (this.unidbgProperties.isAsync()) {
            while (true) {
                if ((worker = pool.borrow(2, TimeUnit.SECONDS)) == null) {
                    continue;
                }
                result = worker.doAfAcEncIdWork();
                pool.release(worker);
                break;
            }
        } else {
            synchronized (this) {
                result = this.doAfAcEncIdWork();
            }
        }

        return CompletableFuture.completedFuture(result);
    }

    private String doAfAcEncDatWork() {
        // 先调用一下hook注入
        shopeeSGAfAcEncService.hookGetBatteryCapacity();
        return shopeeSGAfAcEncService.getAfAcEncDat();
    }

    private String doAfAcEncIdWork() {
        return shopeeSGAfAcEncService.getAfAcEncId();
    }

    @SneakyThrows
    @Override
    public void destroy() {
        shopeeSGAfAcEncService.destroy();
    }
}
