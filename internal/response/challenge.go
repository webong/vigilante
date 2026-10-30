package response

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"html/template"
	"math/bits"
	"net/http"
	"strings"
	"time"
)

const ChallengePath = "/.vigilante/challenge"

type Challenger struct{ secret []byte }

func NewChallenger() *Challenger {
	secret := make([]byte, 32)
	_, _ = rand.Read(secret)
	return &Challenger{secret: secret}
}
func (c *Challenger) Passed(r *http.Request, ip string, now time.Time) bool {
	cookie, err := r.Cookie("vigilante_pass")
	return err == nil && c.check("pass", cookie.Value, ip, now)
}
func (c *Challenger) Serve(w http.ResponseWriter, r *http.Request, ip string, now time.Time) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusForbidden)
	_ = challengePage.Execute(w, map[string]any{"Challenge": c.sign("challenge", ip, now.Add(2*time.Minute)), "Difficulty": 16, "Return": r.URL.RequestURI(), "Action": ChallengePath})
}
func (c *Challenger) Verify(w http.ResponseWriter, r *http.Request, ip string, now time.Time) {
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if r.Method != http.MethodPost || r.ParseForm() != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	ch, nonce := r.PostForm.Get("c"), r.PostForm.Get("n")
	if r.PostForm.Get("w") == "1" || !c.check("challenge", ch, ip, now) || leadingZeroBits(sha256.Sum256([]byte(ch+":"+nonce))) < 16 {
		http.Error(w, "challenge failed", http.StatusForbidden)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "vigilante_pass", Value: c.sign("pass", ip, now.Add(time.Hour)), Path: "/", MaxAge: 3600, HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteLaxMode})
	ret := r.PostForm.Get("r")
	if !strings.HasPrefix(ret, "/") || strings.HasPrefix(ret, "//") || strings.HasPrefix(ret, "/\\") {
		ret = "/"
	}
	http.Redirect(w, r, ret, http.StatusSeeOther)
}
func (c *Challenger) sign(purpose, ip string, exp time.Time) string {
	buf := binary.BigEndian.AppendUint64(nil, uint64(exp.Unix()))
	return base64.RawURLEncoding.EncodeToString(append(buf, c.mac(purpose, ip, buf)...))
}
func (c *Challenger) check(purpose, token, ip string, now time.Time) bool {
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(raw) != 24 {
		return false
	}
	exp := time.Unix(int64(binary.BigEndian.Uint64(raw[:8])), 0)
	return now.Before(exp) && hmac.Equal(raw[8:], c.mac(purpose, ip, raw[:8]))
}
func (c *Challenger) mac(purpose, ip string, exp []byte) []byte {
	m := hmac.New(sha256.New, []byte(purpose+"|"+ip+"|"))
	m.Write(exp)
	return m.Sum(nil)[:16]
}
func leadingZeroBits(sum [32]byte) int {
	n := 0
	for _, b := range sum {
		if b != 0 {
			return n + bits.LeadingZeros8(b)
		}
		n += 8
	}
	return n
}

var challengePage = template.Must(template.New("challenge").Parse(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex"><title>Checking your browser</title></head><body><main><h1>Checking your browser</h1><p>This takes a second.</p><noscript><p>Turn on JavaScript to continue.</p></noscript><form id="f" method="post" action="{{.Action}}"><input type="hidden" name="c" value="{{.Challenge}}"><input type="hidden" name="n" id="n"><input type="hidden" name="w" id="w"><input type="hidden" name="r" value="{{.Return}}"></form></main><script>(async()=>{document.getElementById("w").value=navigator.webdriver?"1":"0";const c={{.Challenge}},bits={{.Difficulty}},enc=new TextEncoder();const ok=(h)=>{let z=0;for(const b of h){if(b===0){z+=8;continue}z+=Math.clz32(b)-24;break}return z>=bits};for(let n=0;;n++){const h=new Uint8Array(await crypto.subtle.digest("SHA-256",enc.encode(c+":"+n)));if(ok(h)){document.getElementById("n").value=n;document.getElementById("f").submit();return}}})().catch(()=>{});</script></body></html>`))
