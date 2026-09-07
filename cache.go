package main

import (
	"container/list"
	"sync"
	"time"

	"github.com/miekg/dns"
)

type cacheKey struct {
	server, name string
	qtype        uint16
}

type cachedReply struct {
	key             cacheKey
	msg             *dns.Msg
	stored, expires time.Time
}

type replyCache struct {
	mu      sync.Mutex
	entries map[cacheKey]*list.Element
	order   *list.List
	limit   int
	now     func() time.Time
}

func newReplyCache(limit int) *replyCache {
	return &replyCache{entries: make(map[cacheKey]*list.Element), order: list.New(), limit: limit, now: time.Now}
}

func (c *replyCache) get(key cacheKey) (*dns.Msg, bool) {
	if c.limit == 0 {
		return nil, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	element, ok := c.entries[key]
	if !ok {
		return nil, false
	}
	entry := element.Value.(cachedReply)
	now := c.now()
	if !now.Before(entry.expires) {
		c.remove(element)
		return nil, false
	}
	c.order.MoveToFront(element)
	msg := entry.msg.Copy()
	age := uint32(now.Sub(entry.stored) / time.Second)
	for _, section := range [][]dns.RR{msg.Answer, msg.Ns, msg.Extra} {
		for _, rr := range section {
			if rr.Header().Rrtype == dns.TypeOPT {
				continue // OPT's TTL field contains flags, not a cache lifetime.
			}
			if rr.Header().Ttl > age {
				rr.Header().Ttl -= age
			} else {
				rr.Header().Ttl = 0
			}
		}
	}
	return msg, true
}

func (c *replyCache) put(key cacheKey, msg *dns.Msg) {
	if c.limit == 0 {
		return
	}
	ttl := cacheTTL(msg)
	if ttl == 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if old, ok := c.entries[key]; ok {
		c.remove(old)
	}
	for c.order.Len() >= c.limit {
		c.remove(c.order.Back())
	}
	now := c.now()
	entry := cachedReply{key: key, msg: msg.Copy(), stored: now, expires: now.Add(time.Duration(ttl) * time.Second)}
	c.entries[key] = c.order.PushFront(entry)
}

func (c *replyCache) remove(element *list.Element) {
	delete(c.entries, element.Value.(cachedReply).key)
	c.order.Remove(element)
}

// Negative answers need an applicable SOA. RFC 2308 limits their lifetime by
// both the SOA TTL and MINIMUM field; transient failures are never cached.
func cacheTTL(msg *dns.Msg) uint32 {
	if msg == nil || msg.Truncated || len(msg.Question) != 1 ||
		msg.Rcode != dns.RcodeSuccess && msg.Rcode != dns.RcodeNameError {
		return 0
	}
	records, err := answerRecords(msg.Question[0].Name, msg)
	if err != nil {
		return 0
	}
	var ttl uint32 = ^uint32(0)
	if msg.Rcode == dns.RcodeNameError || !records.any() {
		foundSOA := false
		for _, rr := range msg.Ns {
			if soa, ok := rr.(*dns.SOA); ok && soa.Hdr.Class == dns.ClassINET && dns.IsSubDomain(soa.Hdr.Name, msg.Question[0].Name) {
				ttl = min(ttl, soa.Hdr.Ttl, soa.Minttl)
				foundSOA = true
			}
		}
		if !foundSOA {
			return 0
		}
	}
	for _, rr := range msg.Answer {
		ttl = min(ttl, rr.Header().Ttl)
	}
	if ttl == ^uint32(0) {
		return 0
	}
	return ttl
}
