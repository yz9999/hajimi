"""Deterministic regression for the pinned peer's FIN-only budget defect."""
import unittest

from aioquic.quic.packet_builder import QuicDeliveryState
from aioquic.quic.stream import QuicStreamSender
import quic_interop_server as fixture


def drained_sender():
    sender = QuicStreamSender(stream_id=4, writable=True)
    # HY1's response + prefix + test payload end at the observed offset 20020.
    sender.write(b"x" * 20020)
    frame = sender.get_frame(max_size=20020)
    assert len(frame.data) == 20020 and not frame.fin
    sender.on_data_delivery(QuicDeliveryState.ACKED, 0, 20020, False)
    sender.write(b"", end_stream=True)
    return sender


class EmptyFinBudgetTests(unittest.TestCase):
    @unittest.skipUnless(fixture.AIOQUIC_VERSION == "1.3.0", "Original defect is pinned to aioquic 1.3.0")
    def test_original_peer_deterministically_consumes_unserializable_fin(self):
        sender = drained_sender()
        frame = fixture._original_get_frame(sender, max_size=-1)
        self.assertTrue(frame.fin)
        self.assertEqual(frame.offset, 20020)
        self.assertFalse(sender._pending_eof)
        self.assertFalse(sender._acked_fin)
        # The later packet-builder capacity rejection has no delivery handler
        # to requeue this frame: a second call has permanently lost the FIN.
        self.assertIsNone(fixture._original_get_frame(sender, max_size=0))

    def test_empty_stream_preserves_fin_when_budget_is_negative(self):
        sender = QuicStreamSender(stream_id=4, writable=True)
        sender.write(b"", end_stream=True)
        for budget in (-1, -128, -4096):
            self.assertIsNone(sender.get_frame(max_size=budget))
            self.assertTrue(sender._pending_eof)
        frame = sender.get_frame(max_size=0)
        self.assertTrue(frame.fin)
        self.assertEqual(frame.offset, 0)
        self.assertEqual(frame.data, b"")

    def test_drained_payload_fin_is_sent_and_acknowledged_after_budget_recovers(self):
        sender = drained_sender()
        self.assertIsNone(sender.get_frame(max_size=-1))
        self.assertTrue(sender._pending_eof)
        self.assertFalse(sender.is_finished)
        frame = sender.get_frame(max_size=0)
        self.assertTrue(frame.fin)
        self.assertEqual(frame.offset, 20020)
        sender.on_data_delivery(QuicDeliveryState.ACKED, 20020, 20020, True)
        self.assertTrue(sender.is_finished)

    def test_payload_fin_keeps_wire_bytes_unchanged(self):
        sender = QuicStreamSender(stream_id=4, writable=True)
        sender.write(b"payload", end_stream=True)
        self.assertIsNone(sender.get_frame(max_size=-1))
        self.assertIsNone(sender.get_frame(max_size=0))
        frame = sender.get_frame(max_size=7)
        self.assertEqual(frame.data, b"payload")
        self.assertTrue(frame.fin)


if __name__ == "__main__":
    unittest.main(verbosity=2)
