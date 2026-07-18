package hydra

import "time"

// The device channel (SPEC §3.13, hydra.c:1160-1170, 1888-1905): an
// out-of-band datagram stream multiplexed into the session. Each
// DEVDATA carries a session-unique non-zero id and is retransmitted
// until the matching DEVDACK arrives. DEVDATA/DEVDACK never reset
// braindead — chat keepalives must not mask a stalled transfer.

// queueDev accepts a datagram from SendDevice. The device tag occupies
// a fixed 4-byte field (3 chars + NUL) in HydraCom-lineage parsers, so
// short names are padded and long ones truncated.
func (b *batch) queueDev(req devRequest) {
	dev := req.device
	if len(dev) > 3 {
		dev = dev[:3]
	}
	for len(dev) < 3 {
		dev += " "
	}
	b.devQueue = append(b.devQueue, devDataPkt{device: dev, payload: req.payload})
}

// devAction promotes the queue head and (re)sends the in-flight
// datagram. Sending is gated on DEV being negotiated and the TX machine
// being inside the session body (txstate > RINIT, < END —
// hydra_devfree, hydra.c:176-182).
func (b *batch) devAction() error {
	if b.devState == htdDone && b.devPending == nil && len(b.devQueue) > 0 {
		next := b.devQueue[0]
		b.devQueue = b.devQueue[1:]
		b.devTxID++
		next.id = b.devTxID
		b.devPending = &next
		b.devState = htdData
	}
	if b.devState != htdData {
		return nil
	}
	if b.txState <= htxRinit || b.txState >= htxEnd {
		return nil // not yet / no longer eligible; retry next pass
	}
	if b.opts&capDEV == 0 {
		// Peer never negotiated DEV — drop silently.
		b.devPending = nil
		b.devState = htdDone
		return nil
	}
	if err := b.write(pktDEVDATA, marshalDevData(*b.devPending)); err != nil {
		return err
	}
	b.devTimer = time.Now().Add(b.cfg.Timeout)
	b.devState = htdDack
	return nil
}

// devTimeout retries the in-flight DEVDATA; unlike file retries, the
// original aborts the whole session after 10 losses (hydra.c:1365-1377).
func (b *batch) devTimeout() error {
	b.devRetries++
	if b.devRetries > b.cfg.MaxRetries {
		return ErrMaxRetries
	}
	if b.devState == htdDack {
		b.devState = htdData
	}
	return nil
}

// devRx processes incoming DEVDATA (hydra.c:1888-1896): dedupe by id,
// deliver to the handler if bound, and ALWAYS acknowledge — even
// duplicates re-ack with the stored id.
func (b *batch) devRx(pkt packet) error {
	d, err := parseDevData(pkt.payload)
	if err != nil {
		return nil
	}
	if d.id != b.devRxID {
		b.devRxID = d.id
		if b.s.dev != nil {
			// The wire allows an arbitrary NUL-terminated tag; the
			// contract promises a 3-char name.
			name := d.device
			if len(name) > 3 {
				name = name[:3]
			}
			b.s.dev.OnDeviceData(name, d.payload)
		}
	}
	return b.write(pktDEVDACK, marshalDevAck(b.devRxID))
}

// devDack processes DEVDACK (hydra.c:1900-1905): a matching id completes
// the in-flight datagram.
func (b *batch) devDack(pkt packet) {
	id, err := parseDevAck(pkt.payload)
	if err != nil || b.devState != htdDack || b.devPending == nil {
		return
	}
	if id == b.devPending.id {
		b.devPending = nil
		b.devRetries = 0
		b.devTimer = time.Time{}
		b.devState = htdDone
	}
}
