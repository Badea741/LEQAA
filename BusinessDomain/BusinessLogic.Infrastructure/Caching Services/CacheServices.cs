﻿using System;
using System.Threading.Tasks;
using Microsoft.Extensions.Caching.Distributed;
using Newtonsoft.Json;
using BusinessLogic.Infrastructure.Caching_Services;
using StackExchange.Redis;
using BusinessLogic.Application.Interfaces;
using Microsoft.EntityFrameworkCore.Metadata.Internal;
using Microsoft.Graph;

namespace BusinessLogic.Infrastructure.Caching_Services
{
    public class CacheService : ICacheService
    {
        /*  private readonly IDatabase _cache;*/
       
        private readonly IDistributedCache _distributedCache;

        public CacheService(IDistributedCache distributedCache)
        {
            /*   var redis = ConnectionMultiplexer.Connect("localhost:6379");
               _cache = redis.GetDatabase();*/
            _distributedCache = distributedCache;
        }

        public Task<T> GetAsync<T>(string key)
        {
            throw new NotImplementedException();
        }

        public async Task<T> handlCaching<T>(string key, Func<T> query)
        {
            var cacheKey = $"cache_{Thread.CurrentThread.CurrentCulture.Name}_{key}";
            var cacheData = await _distributedCache.GetStringAsync(cacheKey);

            if (!string.IsNullOrEmpty(cacheData))
            {
                return JsonConvert.DeserializeObject<T>(cacheData)!;
            }

            var data = query();
            DateTimeOffset expTime = DateTime.Now.AddSeconds(30);

            var expiryTime = expTime.DateTime.Subtract(DateTime.Now);
            var settings = new JsonSerializerSettings
            {
                ReferenceLoopHandling = ReferenceLoopHandling.Ignore
            };

            await _distributedCache.SetStringAsync(cacheKey, JsonConvert.SerializeObject(data, settings), new DistributedCacheEntryOptions { AbsoluteExpirationRelativeToNow = expiryTime });

            return data;
        }


        public object RemoveData(string key)
        {
            throw new NotImplementedException();
        }

        public bool SetData<T>(string key, T data, DateTimeOffset expiration)
        {
            throw new NotImplementedException();
        }
    }
}