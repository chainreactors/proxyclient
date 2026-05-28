package ssh

import (
	"context"
	"errors"
	"io/ioutil"
	"net/url"
	"sync"

	"github.com/chainreactors/proxyclient"
	gossh "golang.org/x/crypto/ssh"
)

func init() {
	proxyclient.RegisterScheme("SSH", newSSHProxyClient)
}

type sshClientCache struct {
	sync.RWMutex
	clients map[string]*gossh.Client
}

var globalSSHCache = &sshClientCache{
	clients: make(map[string]*gossh.Client),
}

func (c *sshClientCache) getClient(key string) *gossh.Client {
	c.RLock()
	defer c.RUnlock()
	return c.clients[key]
}

func (c *sshClientCache) setClient(key string, client *gossh.Client) {
	c.Lock()
	defer c.Unlock()
	c.clients[key] = client
}

func newSSHProxyClient(proxy *url.URL, upstreamDial proxyclient.Dial) (proxyclient.Dial, error) {
	if proxy.User == nil {
		return nil, errors.New("must set username")
	}

	cacheKey := proxy.String()

	if client := globalSSHCache.getClient(cacheKey); client != nil {
		return proxyclient.WrapDialerContext(client.Dial).TCPOnly, nil
	}

	auth, err := sshAuth(proxy)
	if err != nil {
		return nil, err
	}
	conf := &gossh.ClientConfig{
		User:            proxy.User.Username(),
		Auth:            auth,
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
	}
	conn, err := upstreamDial(context.Background(), "tcp", proxy.Host)
	if err != nil {
		return nil, err
	}
	sshConn, sshChans, sshRequests, err := gossh.NewClientConn(conn, proxy.Host, conf)
	if err != nil {
		return nil, err
	}
	sshClient := gossh.NewClient(sshConn, sshChans, sshRequests)

	globalSSHCache.setClient(cacheKey, sshClient)

	return proxyclient.WrapDialerContext(sshClient.Dial).TCPOnly, nil
}

func sshAuth(proxy *url.URL) ([]gossh.AuthMethod, error) {
	var methods []gossh.AuthMethod
	publicKey := proxy.Query().Get("public-key")
	if publicKey != "" {
		buffer, err := ioutil.ReadFile(publicKey)
		if err != nil {
			return nil, err
		}
		key, err := gossh.ParsePrivateKey(buffer)
		if err != nil {
			return nil, err
		}
		methods = append(methods, gossh.PublicKeys(key))
	}
	if password, ok := proxy.User.Password(); ok {
		methods = append(methods, gossh.Password(password))
	}
	return methods, nil
}
