package org.i3mid.services;

import org.i3mid.models.UserInput;

import io.quarkus.cache.Cache;
import io.quarkus.cache.CacheInvalidate;
import io.quarkus.cache.CacheName;
import io.quarkus.cache.CaffeineCache;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

@ApplicationScoped
public class UserCacheService {

    @Inject
    @CacheName("user-lookup-cache")
    Cache cache;

    public void putUser(String uid, UserInput userInput) {
        cache.as(CaffeineCache.class).put(uid, java.util.concurrent.CompletableFuture.completedFuture(userInput));
    }

    public UserInput getUser(String uid) {
        try {
            return (UserInput) cache.as(CaffeineCache.class)
                    .getIfPresent(uid)
                    .get();
        } catch (Exception e) {
            return null;
        }
    }

    @CacheInvalidate(cacheName = "user-lookup-cache")
    public void invalidateUser(String uid) {
    }
}
