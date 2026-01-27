// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice Minimal mailbox harness used by CLI integration tests.
contract MailboxHarness {
    bytes32 public lastReservationId;
    address public lastPoster;
    bytes public lastEnvelope;

    event PreSigPublished(bytes32 indexed reservationId, address indexed desk, bytes envelope);

    function publishPreSig(bytes32 reservationId, bytes calldata envelope) external {
        lastReservationId = reservationId;
        lastPoster = msg.sender;
        lastEnvelope = envelope;
        emit PreSigPublished(reservationId, msg.sender, envelope);
    }
}
