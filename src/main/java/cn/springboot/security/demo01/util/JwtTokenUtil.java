package cn.springboot.security.demo01.util;

import io.jsonwebtoken.*;
import org.springframework.stereotype.Component;

import java.io.Serializable;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/**
 * @Author: 石云鹏
 * @date: 2020/7/8 17:31
 * @description: TODO
 **/
@Component
public class JwtTokenUtil implements Serializable {

    private static final long serialVersionUID = -4324967L;

    /**
     * @param expireMillis     JWT的过期时间
     * @param username 用户名
     * @param key 密钥
     * @return 用户登录成功后生成的 JWT 使用的Hs256算法 私钥使用 用户密码
     */
    public static String createJWT(long expireMillis, String username, String key) {
        //指定签名的时候使用的签名算法，也就是header中的 算法
        SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS256;
        //生成JWT的时间
        long createMillis = System.currentTimeMillis();
        Date createTime = new Date(createMillis);

        //创建payload的私有声明(根据特定的业务需要添加，如果要拿这个做验证,一般是需要和JWT的接受方提前沟通)
        Map<String, Object> claims = new HashMap<String, Object>();
        claims.put("userName", username);


        //生成签名是使用的密钥 secret ，这个方法本地封装的
        // 一般可以从本地配置文件中读取，切记这个密钥不能不能外露 一旦客户端知道 密钥意味着 客户端可以自己签发密钥
//        String key = userEntity.getUserPassword();

        //生成签发人
        String subject = username;

        //下面就是在为payload添加各种标准声明和私有声明了
        //这里其实就是new一个JWTBuild，设置jwt的body
        JwtBuilder jwtBuilder = Jwts.builder()
                //插入 私有声明
                .setClaims(claims)
                //设置JWT的唯一标识
                .setId(UUID.randomUUID().toString())
                //设置 创建时间
                .setIssuedAt(createTime)
                //设置 唯一所有人 可以存放主键之类的不重复字段作为唯一标识
                .setSubject(subject)
                //设置算法 和 密钥
                .signWith(signatureAlgorithm, key);
        //判断过期时间 如果大于0 则设置过期时间
        if (expireMillis >= 0) {
            long expMillis = createMillis + expireMillis*1000;
            Date exp = new Date(expMillis);
            //设置过期时间
            jwtBuilder.setExpiration(exp);
        }
        return jwtBuilder.compact();
    }

    /**
     * Token解析
     * @param token 被解析 JWT
     * @param key 用户实体对象 可以通过数据库查询
     * @return 返回payload中存的数据
     */
    public static String  parseJWT(String token,String key){
        //根据用户获取密钥
//        String key = userEntity.getUserPassword();
        //获取DefaultJwtParser

        Claims claims = Jwts.parser()
                //设置 密钥
                .setSigningKey(key)
                //设置需要解析的 token
                .parseClaimsJws(token).getBody();
        return claims.get("userName").toString();
    }

    /**
     * 验证 token信息 是否正确
     * @param token 被解析 JWT
     * @param key 密钥
     * @return 是否正确
     */
    public static Boolean verify(String token,String key){
        //获取签名密钥
        //String key = userEntity.getUserPassword();
        //获取DefaultJwtParser
        try{
            Jwts.parser()
                    //设置 密钥
                    .setSigningKey(key)
                    //设置需要解析的 token
                    .parseClaimsJws(token).getBody();
            return true;
        }catch (Exception e){
            return false;
        }
    }

    /**
     * 解析Claims
     *
     * @param token
     * @return
     */
    public static Claims getClaim(String token,String key) {
        Claims claims = null;
        try {
            claims = Jwts.parser()
                    .setSigningKey(key)
                    .parseClaimsJws(token)
                    .getBody();
        } catch (Exception e) {
            //e.printStackTrace();
        }
        return claims;
    }


    /**
     * 获取jwt失效时间
     */
    public static Date getExpiration(String token,String key) {
        return getClaim(token,key).getExpiration();
    }


    /**
     * 验证token是否失效
     *
     * @param token
     * @return true:过期   false:没过期
     */
    public static boolean isExpired(String token,String key) {
        try {
            final Date expiration = getExpiration(token,key);
            return expiration.before(new Date());
        } catch (ExpiredJwtException expiredJwtException) {
            return true;
        }
    }
}
