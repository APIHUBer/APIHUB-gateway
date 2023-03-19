package com.example.apihubgateway;

import com.example.apihubclientsdk.utils.SignUtils;
import com.example.apihubcommon.model.entity.InterfaceInfo;
import com.example.apihubcommon.model.entity.User;
import com.example.apihubcommon.service.InnerInterfaceInfoService;
import com.example.apihubcommon.service.InnerUserInterfaceInfoService;
import com.example.apihubcommon.service.InnerUserService;
import lombok.extern.slf4j.Slf4j;
import org.apache.dubbo.config.annotation.DubboReference;
import org.reactivestreams.Publisher;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferFactory;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.http.server.reactive.ServerHttpResponseDecorator;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Global Filter
 * @author jayingyoung
 */
@Slf4j
@Component
public class CustomGlobalFilter implements GlobalFilter, Ordered {

    @DubboReference
    private InnerUserService innerUserService;

    @DubboReference
    private InnerInterfaceInfoService innerInterfaceInfoService;

    @DubboReference
    private InnerUserInterfaceInfoService innerUserInterfaceInfoService;

    public static final List<String> IP_WHITE_LIST = Arrays.asList("127.0.0.1");

    public static final String INTERFACE_HOST = "http://localhost:8123";

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        // 1. 请求日志 - request log
        ServerHttpRequest request = exchange.getRequest();
        String path = INTERFACE_HOST + request.getPath().value();
        String method = request.getMethod().toString();
        log.info("RequestId: " + request.getId());
        log.info("Request Path: " + path);
        log.info("Request Method: " + method);
        log.info("Request Params: " + request.getQueryParams());
        String sourceAddress = request.getLocalAddress().getHostString();
        log.info("Request Address: " + sourceAddress);
        log.info("Request Remote Address: " + request.getRemoteAddress());
        ServerHttpResponse response = exchange.getResponse();
        // 2. 黑白名单 - Black and white list
        if(!IP_WHITE_LIST.contains(sourceAddress)){
            response.setStatusCode(HttpStatus.FORBIDDEN);
            return response.setComplete();
        }

        // 3. 用户鉴权 - User authentication
        HttpHeaders headers = request.getHeaders();
        String accessKey = headers.getFirst("accessKey");
        String nonce = headers.getFirst("nonce");
        String timestamp = headers.getFirst("timestamp");
        String sign = headers.getFirst("sign");
        String body = headers.getFirst("body");
        // todo: The actual situation should be checked in the database
        User invokeUser = null;
        try {
            invokeUser = innerUserService.getInvokeUser(accessKey);
        }catch (Exception e){
           log.error("getInvokeUser error", e);
            return handleNoAuth(response);
        }

//        if(!accessKey.equals("yupi")){
//            return handleNoAuth(response);
//        }
        if(Long.parseLong(nonce) > 10000L){
            return handleNoAuth(response);
        }
        // timestamp cannot more than 5 mins
        long currentTime = System.currentTimeMillis() / 1000;
        final Long FIVE_MINUTES = 60 *5L;
        if((currentTime - Long.parseLong(timestamp)) >= FIVE_MINUTES){
            return handleNoAuth(response);
        }
        // todo: The actual situation should be check secretKey in database
        String secretKey = invokeUser.getSecretKey();
        String serverSign = SignUtils.genSign(body, secretKey);
        if(sign == null || !sign.equals(serverSign)){
            return handleNoAuth(response);
        }

        // 4. 判断请求的模拟接口是否存在 - Check whether the simulated interface of the request exists
        InterfaceInfo interfaceInfo = null;
        try {
            interfaceInfo = innerInterfaceInfoService.getInterfaceInfo(path, method);
        }catch (Exception e){
            log.error("getInterfaceInfo error", e);
            return handleNoAuth(response);
        }
        if(interfaceInfo == null){
            return handleNoAuth(response);
        }

        // todo: whether or not have more invoke count

        // 5. 响应日志 - response log - 请求转发，调用模拟接口 - Request forward, call mock interface
//        Mono<Void> filter = chain.filter(exchange);
        return handleResponse(exchange, chain, interfaceInfo.getId(), invokeUser.getId());

    }


    /**
     * Handle Response
     * @param exchange
     * @param chain
     * @return
     */
    public Mono<Void> handleResponse(ServerWebExchange exchange, GatewayFilterChain chain, long InterfaceInfoId, long userId){
        try {
            ServerHttpResponse originalResponse = exchange.getResponse();
            DataBufferFactory bufferFactory = originalResponse.bufferFactory();
            // Status code
            HttpStatus statusCode = originalResponse.getStatusCode();
            if(statusCode == HttpStatus.OK){
                // decorate
                ServerHttpResponseDecorator decoratedResponse = new ServerHttpResponseDecorator(originalResponse) {
                    @Override
                    public Mono<Void> writeWith(Publisher<? extends DataBuffer> body) {
                        log.info("body instanceof Flux: {}", (body instanceof Flux));
                        if (body instanceof Flux) {
                            Flux<? extends DataBuffer> fluxBody = Flux.from(body);
                            // 往返回值里写数据
                            return super.writeWith(
                                fluxBody.map(dataBuffer -> {
                                    // 7. invoke success, invokeCount + 1
                                    try {
                                        innerUserInterfaceInfoService.invokeCount(InterfaceInfoId, userId);
                                    }catch (Exception e){
                                        log.error("invokeCount error", e);
                                    }
                                    byte[] content = new byte[dataBuffer.readableByteCount()];
                                    dataBuffer.read(content);
                                    DataBufferUtils.release(dataBuffer);//释放掉内存
                                    // 构建日志
                                    StringBuilder sb2 = new StringBuilder(200);
                                    List<Object> rspArgs = new ArrayList<>();
                                    rspArgs.add(originalResponse.getStatusCode());
                                    //rspArgs.add(requestUrl);
                                    String data = new String(content, StandardCharsets.UTF_8);//data
                                    sb2.append(data);
                                    // 打印日志
                                    log.info("Response Result: " + data);
                                    return bufferFactory.wrap(content);
                            }));
                        } else {
                            // 8. invoke fail, 返回一个规范的错误码
                            log.error("<--- {} 响应code异常", getStatusCode());
                            // handleInvokeError();
                        }
                        return super.writeWith(body);
                    }
                };
                return chain.filter(exchange.mutate().response(decoratedResponse).build());
            }
            return chain.filter(exchange);//降级处理返回数据
        }catch (Exception e){
            log.error("gateway log exception. " + e);
            return chain.filter(exchange);
        }
    }

    @Override
    public int getOrder() {
        return -1;
    }

    public Mono<Void> handleNoAuth(ServerHttpResponse response){
        response.setStatusCode(HttpStatus.FORBIDDEN);
        return response.setComplete();
    }

    public Mono<Void> handleInvokeError(ServerHttpResponse response){
        response.setStatusCode(HttpStatus.INTERNAL_SERVER_ERROR);
        return response.setComplete();
    }
}

