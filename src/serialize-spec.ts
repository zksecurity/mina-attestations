import { Claim, Constant, Spec, type Input } from './program-spec.ts';
import { Node } from './operation.ts';
import {
  type HttpsInputContext,
  type ZkAppInputContext,
} from './presentation.ts';
import {
  type SerializedValue,
  serializeNestedProvable,
  serializeProvable,
  serializeProvableType,
  deserializeNestedProvable,
  deserializeProvable,
  deserializeProvableType,
} from './serialize-provable.ts';
import { assert, mapObject } from './util.ts';
import { Credential } from './credential-index.ts';
import type { InputJSON, NodeJSON, SpecJSON } from './validation.ts';

export {
  type SerializedValue,
  type SerializedContext,
  serializeNode,
  deserializeNode,
  serializeInput,
  deserializeInput,
  serializeSpec,
  deserializeSpec,
  validateSpecHash,
  serializeInputContext,
  deserializeInputContext,
};

function serializeSpec(spec: Spec): SpecJSON {
  return {
    inputs: mapObject(spec.inputs, (input) => serializeInput(input)),
    assert: serializeNode(spec.assert),
    outputClaim: serializeNode(spec.outputClaim),
  };
}
function deserializeSpec(spec: SpecJSON): Spec {
  let inputs = mapObject(spec.inputs, (input) => deserializeInput(input));
  return {
    inputs,
    assert: deserializeNode(inputs, spec.assert),
    outputClaim: deserializeNode(inputs, spec.outputClaim),
  };
}

function serializeInput(input: Input): InputJSON {
  switch (input.type) {
    case 'constant': {
      return {
        type: 'constant',
        data: serializeProvableType(input.data),
        value: serializeProvable(input.value).value,
      };
    }
    case 'claim': {
      return {
        type: 'claim',
        data: serializeNestedProvable(input.data),
      };
    }
    default: {
      assert('credentialType' in input, 'Invalid input type');
      return Credential.specToJSON(input);
    }
  }
}
function deserializeInput(input: InputJSON): Input {
  let type = input.type;
  switch (input.type) {
    case 'constant':
      return Constant(
        deserializeProvableType(input.data),
        deserializeProvable({ ...input.data, value: input.value })
      );
    case 'claim':
      return Claim(deserializeNestedProvable(input.data));
    case 'credential': {
      return Credential.specFromJSON(input);
    }
    default:
      throw Error(`Invalid input type: ${type}`);
  }
}

function serializeNode(node: Node): NodeJSON {
  switch (node.type) {
    case 'constant': {
      return {
        type: 'constant',
        data: serializeProvable(node.data),
      };
    }
    case 'root': {
      return { type: 'root' };
    }
    case 'owner':
    case 'credential':
    case 'issuer':
    case 'issuerPublicKey':
    case 'verificationKeyHash':
    case 'publicInput':
      return node;

    case 'property': {
      return {
        type: 'property',
        key: node.key,
        inner: serializeNode(node.inner),
      };
    }
    case 'and':
      return {
        type: node.type,
        inputs: node.inputs.map(serializeNode),
      };
    case 'equals':
    case 'lessThan':
    case 'lessThanEq':
    case 'or':
    case 'add':
    case 'sub':
    case 'mul':
    case 'div':
      return {
        type: node.type,
        left: serializeNode(node.left),
        right: serializeNode(node.right),
      };
    case 'equalsOneOf': {
      return {
        type: 'equalsOneOf',
        input: serializeNode(node.input),
        options: Array.isArray(node.options)
          ? node.options.map(serializeNode)
          : serializeNode(node.options),
      };
    }
    case 'hash':
      return {
        type: node.type,
        inputs: node.inputs.map(serializeNode),
        prefix: node.prefix ?? null,
      };
    case 'not':
      return {
        type: node.type,
        inner: serializeNode(node.inner),
      };
    case 'ifThenElse':
      return {
        type: 'ifThenElse',
        condition: serializeNode(node.condition),
        thenNode: serializeNode(node.thenNode),
        elseNode: serializeNode(node.elseNode),
      };
    case 'record': {
      const serializedData: Record<string, any> = {};
      for (const [key, value] of Object.entries(node.data)) {
        serializedData[key] = serializeNode(value);
      }
      return {
        type: 'record',
        data: serializedData,
      };
    }
    case 'compute':
      throw Error('Cannot serialize compute node');
    default:
      node satisfies never;
      throw Error(`Invalid node type: ${(node as Node).type}`);
  }
}

function deserializeNode(root: any, node: NodeJSON): Node {
  let type = node.type;
  switch (node.type) {
    case 'constant':
      return {
        type: 'constant',
        data: deserializeProvable(node.data),
      };
    case 'root':
      return { type: 'root', input: root };

    case 'owner':
    case 'credential':
    case 'issuer':
    case 'issuerPublicKey':
    case 'verificationKeyHash':
    case 'publicInput':
      return node as Node;

    case 'property':
      return {
        type: 'property',
        key: node.key,
        inner: deserializeNode(root, node.inner),
      };
    case 'equals':
    case 'lessThan':
    case 'lessThanEq':
      return {
        type: node.type,
        left: deserializeNode(root, node.left),
        right: deserializeNode(root, node.right),
      };
    case 'equalsOneOf': {
      return {
        type: 'equalsOneOf',
        input: deserializeNode(root, node.input),
        options: Array.isArray(node.options)
          ? node.options.map((o) => deserializeNode(root, o))
          : deserializeNode(root, node.options),
      };
    }
    case 'and':
      return {
        type: node.type,
        inputs: node.inputs.map((i: any) => deserializeNode(root, i)),
      };
    case 'or':
    case 'add':
    case 'sub':
    case 'mul':
    case 'div':
      return {
        type: node.type,
        left: deserializeNode(root, node.left),
        right: deserializeNode(root, node.right),
      };
    case 'hash':
      let result: Node = {
        type: node.type,
        inputs: node.inputs.map((i: any) => deserializeNode(root, i)),
      };
      if (node.prefix !== null) result.prefix = node.prefix;
      return result;
    case 'not':
      return {
        type: node.type,
        inner: deserializeNode(root, node.inner),
      };
    case 'ifThenElse':
      return {
        type: 'ifThenElse',
        condition: deserializeNode(root, node.condition),
        thenNode: deserializeNode(root, node.thenNode),
        elseNode: deserializeNode(root, node.elseNode),
      };
    case 'record':
      const deserializedData: Record<string, Node> = {};
      for (const [key, value] of Object.entries(node.data)) {
        deserializedData[key] = deserializeNode(root, value as any);
      }
      return {
        type: 'record',
        data: deserializedData,
      };
    default:
      node satisfies never;
      throw Error(`Invalid node type: ${type}`);
  }
}

type SerializedContext =
  | { type: 'https'; action: string; serverNonce: SerializedValue }
  | { type: 'zk-app'; action: SerializedValue; serverNonce: SerializedValue };

function serializeInputContext(
  context: undefined | ZkAppInputContext | HttpsInputContext
): null | SerializedContext {
  if (context === undefined) return null;

  let serverNonce = serializeProvable(context.serverNonce);

  switch (context.type) {
    case 'zk-app':
      let action = serializeProvable(context.action);
      return { type: context.type, serverNonce, action };
    case 'https':
      return { type: context.type, serverNonce, action: context.action };
    default:
      throw Error(`Unsupported context type: ${(context as any).type}`);
  }
}
function deserializeInputContext(context: null | SerializedContext) {
  if (context === null) return undefined;
  return {
    type: context.type,
    action:
      context.type === 'zk-app'
        ? deserializeProvable({ _type: 'Field', value: context.action.value })
        : context.action,
    serverNonce: deserializeProvable({
      _type: 'Field',
      value: context.serverNonce.value,
    }),
  };
}

async function hashSpec(serializedSpec: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(serializedSpec);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
}

async function validateSpecHash(
  serializedSpecWithHash: string
): Promise<boolean> {
  const { spec, hash } = JSON.parse(serializedSpecWithHash);
  const recomputedHash = await hashSpec(spec);
  return hash === recomputedHash;
}
