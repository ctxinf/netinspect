// Package observe implements the observe interception mode: no traffic is
// touched. It polls /proc every 200ms, tracks the target's process tree,
// and diffs TCP socket tables to record connection metadata (TCP only;
// UDP/DNS are not covered in this mode).
package observe

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"netinspect/internal/store"
)

type tcpEntry struct {
	localIP   string
	localPort int
	remIP     string
	remPort   int
	state     string
	inode     string
}

// Poll watches rootPID's process tree until ctx is done or the root exits,
// recording new/vanished TCP connections in st.
func Poll(ctx context.Context, rootPID int, st *store.Store) {
	prev := map[string]*connTrack{}
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			finishAll(st, prev)
			return
		case <-ticker.C:
		}
		if !pidAlive(rootPID) {
			// give sockets a beat to vanish, then finish
			time.Sleep(300 * time.Millisecond)
			snapshot(st, prev, rootPID)
			finishAll(st, prev)
			return
		}
		snapshot(st, prev, rootPID)
	}
}

type connTrack struct {
	id    int64
	state string
}

func finishAll(st *store.Store, prev map[string]*connTrack) {
	for key, tr := range prev {
		st.FinishConnection(tr.id, 0, 0, resultFor(tr.state), "")
		delete(prev, key)
	}
}

func resultFor(state string) string {
	switch state {
	case "01": // ESTABLISHED
		return "ok"
	case "02", "03": // SYN_SENT, SYN_RECV
		return "open"
	default:
		return "observed"
	}
}

// snapshot diffs the current TCP view against prev.
func snapshot(st *store.Store, prev map[string]*connTrack, rootPID int) {
	tree := descendents(rootPID)
	// map inode -> (pid, comm)
	inodeOwner := map[string][2]string{}
	for pid := range tree {
		for _, ino := range socketInodes(pid) {
			inodeOwner[ino] = [2]string{strconv.Itoa(pid), commOf(pid)}
		}
	}
	seen := map[string]bool{}
	for _, e := range readTCP() {
		owner, ok := inodeOwner[e.inode]
		if !ok {
			continue
		}
		key := e.inode + "|" + e.remIP + ":" + strconv.Itoa(e.remPort)
		seen[key] = true
		tr, ok := prev[key]
		if !ok {
			pid, _ := strconv.Atoi(owner[0])
			c := &store.Conn{
				PID: pid, Comm: owner[1], Mode: "observe",
				OrigHost: e.remIP, OrigIP: e.remIP, OrigPort: e.remPort,
				Route: "DIRECT", Proto: guessProto(e.remPort), Result: "open",
			}
			id := st.AddConnection(c)
			prev[key] = &connTrack{id: id, state: e.state}
			continue
		}
		tr.state = e.state
	}
	for key, tr := range prev {
		if !seen[key] {
			st.FinishConnection(tr.id, 0, 0, resultFor(tr.state), "")
			delete(prev, key)
		}
	}
}

func guessProto(port int) string {
	if port == 443 || port == 8443 {
		return "tls"
	}
	if port == 80 || port == 8080 {
		return "http"
	}
	return "tcp"
}

// descendents returns rootPID and all its (transitive) children.
func descendents(root int) map[int]bool {
	ppidOf := map[int]int{}
	entries, _ := os.ReadDir("/proc")
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || !e.IsDir() {
			continue
		}
		stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
		if err != nil {
			continue
		}
		// comm may contain spaces/parens: find last ')'
		s := string(stat)
		i := strings.LastIndex(s, ")")
		if i < 0 {
			continue
		}
		rest := strings.Fields(s[i+1:])
		if len(rest) < 2 {
			continue
		}
		ppid, err := strconv.Atoi(rest[1])
		if err != nil {
			continue
		}
		ppidOf[pid] = ppid
	}
	out := map[int]bool{root: true}
	changed := true
	for changed {
		changed = false
		for pid, ppid := range ppidOf {
			if out[ppid] && !out[pid] {
				out[pid] = true
				changed = true
			}
		}
	}
	return out
}

func socketInodes(pid int) []string {
	var out []string
	fds, err := os.ReadDir(fmt.Sprintf("/proc/%d/fd", pid))
	if err != nil {
		return nil
	}
	for _, f := range fds {
		target, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%s", pid, f.Name()))
		if err != nil {
			continue
		}
		if strings.HasPrefix(target, "socket:[") {
			out = append(out, target[len("socket:["):len(target)-1])
		}
	}
	return out
}

func readTCP() []tcpEntry {
	var out []tcpEntry
	for _, f := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		v6 := strings.HasSuffix(f, "6")
		for _, line := range strings.Split(string(data), "\n")[1:] {
			flds := strings.Fields(line)
			if len(flds) < 10 {
				continue
			}
			remIP, remPort := splitAddr(flds[2], v6)
			if remPort == 0 {
				continue
			}
			out = append(out, tcpEntry{
				remIP: remIP, remPort: remPort,
				state: flds[3], inode: flds[9],
			})
		}
	}
	return out
}

func splitAddr(s string, v6 bool) (string, int) {
	parts := strings.Split(s, ":")
	if len(parts) != 2 {
		return "", 0
	}
	p, err := strconv.ParseInt(parts[1], 16, 32)
	if err != nil {
		return "", 0
	}
	ip := hexIP(parts[0], v6)
	return ip, int(p)
}

// hexIP converts /proc little-endian hex IP to a printable address.
func hexIP(h string, v6 bool) string {
	if !v6 {
		if len(h) != 8 {
			return h
		}
		b := make([]byte, 4)
		for i := 0; i < 4; i++ {
			v, _ := strconv.ParseUint(h[i*2:i*2+2], 16, 8)
			b[3-i] = byte(v) // little-endian per 32-bit word
		}
		return fmt.Sprintf("%d.%d.%d.%d", b[0], b[1], b[2], b[3])
	}
	if len(h) != 32 {
		return h
	}
	var words [4]uint32
	for i := 0; i < 4; i++ {
		v, _ := strconv.ParseUint(h[i*8:i*8+8], 16, 32)
		words[i] = uint32(v)
	}
	// each 32-bit word is little-endian; emit network order
	b := make([]byte, 16)
	for i := 0; i < 4; i++ {
		b[i*4+0] = byte(words[i])
		b[i*4+1] = byte(words[i] >> 8)
		b[i*4+2] = byte(words[i] >> 16)
		b[i*4+3] = byte(words[i] >> 24)
	}
	var groups []string
	for i := 0; i < 16; i += 2 {
		groups = append(groups, fmt.Sprintf("%x", int(b[i])<<8|int(b[i+1])))
	}
	return strings.Join(groups, ":")
}

func pidAlive(pid int) bool {
	_, err := os.Stat(fmt.Sprintf("/proc/%d", pid))
	return err == nil
}

func commOf(pid int) string {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}
