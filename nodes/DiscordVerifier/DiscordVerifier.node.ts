import type {
	IExecuteFunctions,
	INodeExecutionData,
	INodeType,
	INodeTypeDescription,
} from 'n8n-workflow';
import { NodeOperationError } from 'n8n-workflow';
import get from 'lodash/get';
import nacl from 'tweetnacl';

export class DiscordVerifier implements INodeType {
	description: INodeTypeDescription = {
		displayName: 'Discord Verifier',
		name: 'discordVerifier',
		group: ['transform'],
		version: 1,
		description: 'Node to verify a discord webhook with signature',
		defaults: {
			name: 'Discord Verifier',
		},
		inputs: ['main'],
		outputs: ['main'],
		properties: [
			// Node properties which the user gets displayed and
			// can change on the node.
			{
				displayName: 'Public Key',
				name: 'publicKey',
				type: 'string',
				required: true,
				default: '',
				placeholder: 'From Discord Bot page',
				description: 'This is the public key from the discord bot page',
			},
			{
				displayName: 'Signature',
				name: 'signature',
				type: 'string',
				required: true,
				default: '',
				placeholder: 'From Discord web hook',
				description: 'This is the signature from the web hook',
			},
			{
				displayName: 'Timestamp',
				name: 'timestamp',
				type: 'string',
				required: true,
				default: '',
				placeholder: 'From Discord Bot page',
				description: 'This is the timestamp from the web hook',
			},
			{
				displayName: 'Input Binary Field',
				name: 'binaryPropertyName',
				type: 'string',
				default: 'data',
				required: true,
				placeholder: 'e.g data',
				hint: 'The name of the input field containing the raw body data from the webhook to be processed',
			},
		],
	};

	// The function below is responsible for actually doing whatever this node
	// is supposed to do. In this case, we're just appending the `myString` property
	// with whatever the user has entered.
	// You can make async calls and use `await`.
	async execute(this: IExecuteFunctions): Promise<INodeExecutionData[][]> {
		const items = this.getInputData();
		let newItems = [];
		// Iterates over all input items and add the key "myString" with the
		// value the parameter "myString" resolves to.
		// (This could be a different value for each item in case it contains an expression)
		for (let itemIndex = 0; itemIndex < items.length; itemIndex++) {
			try {
				const item = items[itemIndex];
				// const options = this.getNodeParameter('options', itemIndex);
				const binaryPropertyName = this.getNodeParameter('binaryPropertyName', itemIndex);

				const rawBody = get(item.binary, binaryPropertyName);
				if (!rawBody) continue;
				// const buf = await this.helpers.getBinaryDataBuffer(itemIndex, binaryPropertyName);
				// console.error(buf);
				const timestamp = this.getNodeParameter('timestamp', itemIndex, '') as string;
				const signature = this.getNodeParameter('signature', itemIndex, '') as string;
				const publicKey = this.getNodeParameter('publicKey', itemIndex, '') as string;


				// rawBody is expected to be a string, not raw bytes
				const isVerified = nacl.sign.detached.verify(
					Buffer.from(timestamp + atob(rawBody.data)),
					Buffer.from(signature, 'hex'),
					Buffer.from(publicKey, 'hex'),
				);

				item.json.verified = isVerified;

				newItems.push(item);
			} catch (error) {
				console.error(error);
				// This node should never fail but we want to showcase how
				// to handle errors.
				if (this.continueOnFail()) {
					items.push({ json: this.getInputData(itemIndex)[0].json, error, pairedItem: itemIndex });
				} else {
					// Adding `itemIndex` allows other workflows to handle this error
					if (error.context) {
						// If the error thrown already contains the context property,
						// only append the itemIndex
						error.context.itemIndex = itemIndex;
						throw error;
					}
					throw new NodeOperationError(this.getNode(), error, {
						itemIndex,
					});
				}
			}
		}
		return [newItems];
	}
}
