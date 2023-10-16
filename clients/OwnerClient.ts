import { type Invoice, type scwMessageEvent, MessageType } from "./Messages";
import {
  Participant,
  StateChannelWallet,
  type StateChannelWalletParams,
} from "./StateChannelWallet";

export class OwnerClient extends StateChannelWallet {
  constructor(params: StateChannelWalletParams) {
    super(params);

    this.attachMessageHandlers();
  }

  private attachMessageHandlers(): void {
    // These handlers are for messages from parties outside of our wallet / channel.
    this.globalBroadcastChannel.onmessage = async (ev: scwMessageEvent) => {
      const req = ev.data;

      if (req.type === MessageType.RequestInvoice) {
        const hash = await this.createNewHash();
        const invoice: Invoice = {
          type: MessageType.Invoice,
          hashLock: hash,
          amount: req.amount,
        };

        // return the invoice to the payer via the same channel they used to request it
        this.globalBroadcastChannel.postMessage(invoice);
      }
    };
  }

  static async create(params: StateChannelWalletParams): Promise<OwnerClient> {
    const instance = new OwnerClient(params);

    if (instance.myRole() !== Participant.Owner) {
      throw new Error("Signer is not owner");
    }

    await OwnerClient.hydrateWithChainData(instance);
    return instance;
  }

  /**
   * Coordinates with the payee to transfer funds to them. Payee is first
   * asked for a hashlock, then the lock is used to forward payment via
   * the intermediary.
   *
   * @param payee the SCBridgeWallet address we want to pay to
   * @param amount the amount we want to pay
   */
  async pay(payee: string, amount: number): Promise<void> {
    // contact `payee` and request a hashlock
    const requestChannel = this.sendGlobalMessage(payee, {
      type: MessageType.RequestInvoice,
      amount,
    });

    const invoice: Invoice = await new Promise((resolve, reject) => {
      // todo: resolve failure on a timeout
      requestChannel.onmessage = (ev: scwMessageEvent) => {
        if (ev.data.type === MessageType.Invoice) {
          resolve(ev.data);
        } else {
          // todo: fallback to L1 payment ?
          reject(new Error("Unexpected message type"));
        }
      };
    });

    // create a state update with the hashlock
    const signedUpdate = await this.addHTLC(amount, invoice.hashLock);

    // send the state update to the intermediary
    this.sendPeerMessage({
      type: MessageType.ForwardPayment,
      target: payee,
      amount,
      hashLock: invoice.hashLock,
      timelock: 0, // todo
      updatedState: signedUpdate,
    });
  }

  // todo: add listener for invoice requests (always accept - they want to pay us)

  // todo: add function to direct L1 payments / general transactions to UserOperations
  //       and forward to intermediary

  // todo: add listener for incoming HTLCs which correspond to some preimage we know.
  //       When they arrive, we claim the funds and maybe clear the invoice in some way.
}