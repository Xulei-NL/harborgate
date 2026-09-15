// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Collections.Generic;

namespace Yarp.Kubernetes.Controller.Caching;

public static class DictionaryExtensions
{
    public static void AddToValuesWithKey<TKey, TValue>(this Dictionary<TKey, List<TValue>> dictionary, TKey key, TValue value)
        where TKey : notnull
    {
        var exist = dictionary.TryGetValue(key, out var list);
        if (exist)
        {
            list.Add(value);
        }
        else
        {
            dictionary[key] = [value];
        }
    }
}
