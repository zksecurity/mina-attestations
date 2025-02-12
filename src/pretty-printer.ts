import type { SerializedType } from './serialize-provable.ts';
import type { JSONValue } from './types.ts';
import type {
  PresentationRequestJSON,
  StoredCredentialJSON,
} from './validation.ts';

export { PrettyPrinter };

/**
 * Methods to print Mina Attestation data types
 * in human readable format.
 */
const PrettyPrinter = {
  printPresentationRequest,
  printVerifierIdentity,
  simplifyCredentialData,
};

function printPresentationRequest(request: PresentationRequestJSON): string {
  let formatted = [
    `Type: ${request.type}`,
    '',
    formatInputsHumanReadable(request.spec.inputs),
    '',
    `Requirements:\n${formatLogicNode(request.spec.assert, 0)}`,
    '',
    `Output:\n${formatLogicNode(request.spec.outputClaim, 0)}`,
    formatClaimsHumanReadable(request.claims),
    request.inputContext
      ? `\nContext:\n- Type: ${request.inputContext.type}\n- Action: ${
          typeof request.inputContext.action === 'string'
            ? request.inputContext.action
            : request.inputContext.action.value
        }\n- Server Nonce: ${request.inputContext.serverNonce.value}`
      : '',
  ].join('\n');

  return formatted;
}

function printVerifierIdentity(
  type: 'zk-app' | 'https',
  verifierIdentity:
    | string
    | { address: string; tokenId: string; network: 'devnet' | 'mainnet' }
): string {
  let verifierUrl =
    type === 'zk-app' &&
    typeof verifierIdentity === 'object' &&
    verifierIdentity !== null
      ? `minascan.io/${verifierIdentity.network}/account/${verifierIdentity.address}`
      : undefined;

  return [
    verifierIdentity !== undefined
      ? `\nVerifier Identity: ${
          type === 'zk-app'
            ? JSON.stringify(verifierIdentity, null, 2)
            : verifierIdentity
        }`
      : '',
    verifierUrl ? `\nSee verifier on Minascan: https://${verifierUrl}` : '',
  ].join('\n');
}

function simplifyCredentialData(storedCredential: StoredCredentialJSON) {
  const data = getCredentialData(storedCredential.credential);
  let simplified: Record<string, JSONValue> = {};
  for (let [key, value] of Object.entries(data)) {
    if (typeof value === 'object' && value !== null) {
      if ('bytes' in value) {
        simplified[key] = value.bytes
          .map((b: { value: string }) => b.value)
          .join('');
      } else if ('value' in value) {
        simplified[key] = value.value;
      } else {
        simplified[key] = value;
      }
    } else {
      simplified[key] = value;
    }
  }
  return simplified;
}

function getCredentialData(
  credential: StoredCredentialJSON['credential']
): Record<
  string,
  string | number | boolean | (SerializedType & { value: JSONValue })
> {
  if ('value' in credential) {
    // TODO get rid of type coercions
    return credential.value.data as any;
  }
  return credential.data;
}

type LogicNode = {
  type: string;
  inputs?: LogicNode[];
  left?: LogicNode;
  right?: LogicNode;
  key?: string;
  inner?: LogicNode;
  data?: Record<string, any>;
  credentialKey?: string;
  input?: LogicNode;
  options?: LogicNode[] | LogicNode;
  condition?: LogicNode;
  thenNode?: LogicNode;
  elseNode?: LogicNode;
};

function extractCredentialFields(data: any): string[] {
  if (!data) return [];

  if (data._type === 'Struct' && data.properties) {
    return Object.keys(data.properties);
  }

  if (data._type === 'DynamicRecord' && data.knownShape) {
    return Object.keys(data.knownShape);
  }

  return Object.keys(data);
}

function buildPropertyPath(node: LogicNode): string {
  let parts: string[] = [];
  let currentNode: LogicNode | undefined = node;

  while (currentNode?.type === 'property') {
    if (!currentNode.key) {
      throw Error("PROPERTY node must have 'key'");
    }
    parts.unshift(currentNode.key);
    currentNode = currentNode.inner;
  }

  return parts.join('.');
}

function formatLogicNode(node: LogicNode, level = 0): string {
  let indent = '  '.repeat(level);

  switch (node.type) {
    case 'and':
      if (!node.inputs) {
        throw Error("AND node must have 'inputs' array");
      }
      if (node.inputs.length === 0) {
        throw Error('AND node must have at least one input');
      }
      return `${indent}All of these conditions must be true:\n${node.inputs
        .map((n) => `${indent}- ${formatLogicNode(n, level + 1)}`)
        .join('\n')}`;

    case 'or':
      if (!node.left || !node.right) {
        throw Error("OR node must have both 'left' and 'right' nodes");
      }
      return `${indent}Either:\n${indent}- ${formatLogicNode(
        node.left,
        level + 1
      )}\n${indent}Or:\n${indent}- ${formatLogicNode(node.right, level + 1)}`;

    case 'equals':
      if (!node.left || !node.right) {
        throw Error("EQUALS node must have both 'left' and 'right' nodes");
      }
      return `${formatLogicNode(node.left)} equals ${formatLogicNode(
        node.right
      )}`;

    case 'equalsOneOf': {
      if (!node.input) {
        throw Error("EQUALS_ONE_OF node must have 'input' node");
      }
      if (!node.options) {
        throw Error("EQUALS_ONE_OF node must have 'options'");
      }
      let input = formatLogicNode(node.input, level);
      let options = Array.isArray(node.options)
        ? node.options.map((o) => formatLogicNode(o, level)).join(', ')
        : formatLogicNode(node.options, level);
      return `${options} contains ${input}`;
    }

    case 'lessThan':
      if (!node.left || !node.right) {
        throw Error("LESS_THAN node must have both 'left' and 'right' nodes");
      }
      return `${formatLogicNode(node.left)} < ${formatLogicNode(node.right)}`;

    case 'lessThanEq':
      if (!node.left || !node.right) {
        throw Error(
          "LESS_THAN_EQ node must have both 'left' and 'right' nodes"
        );
      }
      return `${formatLogicNode(node.left)} ≤ ${formatLogicNode(node.right)}`;

    case 'property': {
      if (!node.key) {
        throw Error("PROPERTY node must have 'key'");
      }

      // If this is the root property, just return the path
      if (node.inner?.type === 'root') {
        return node.key;
      }

      // For nested properties, build the complete path
      return buildPropertyPath(node);
    }

    case 'root':
      return '';

    case 'hash':
      if (!node.inputs) {
        throw Error("HASH node must have 'inputs' array");
      }
      return `hash(${node.inputs
        .map((n) => formatLogicNode(n, level))
        .join(', ')})`;

    case 'issuer':
      if (!node.credentialKey) {
        throw Error("ISSUER node must have 'credentialKey'");
      }
      return `issuer(${node.credentialKey})`;

    case 'not':
      if (!node.inner) {
        throw Error("NOT node must have 'inner' node");
      }
      return `not(${formatLogicNode(node.inner, level)})`;

    case 'add':
      if (!node.left || !node.right) {
        throw Error("ADD node must have both 'left' and 'right' nodes");
      }
      return `(${formatLogicNode(node.left)} + ${formatLogicNode(node.right)})`;

    case 'sub':
      if (!node.left || !node.right) {
        throw Error("SUB node must have both 'left' and 'right' nodes");
      }
      return `(${formatLogicNode(node.left)} - ${formatLogicNode(node.right)})`;

    case 'mul':
      if (!node.left || !node.right) {
        throw Error("MUL node must have both 'left' and 'right' nodes");
      }
      return `(${formatLogicNode(node.left)} x ${formatLogicNode(node.right)})`;

    case 'div':
      if (!node.left || !node.right) {
        throw Error("DIV node must have both 'left' and 'right' nodes");
      }
      return `(${formatLogicNode(node.left)} ÷ ${formatLogicNode(node.right)})`;

    case 'record': {
      if (!node.data) {
        throw Error("RECORD node must have 'data' object");
      }
      if (Object.keys(node.data).length === 0) {
        throw Error('RECORD node must have at least one data field');
      }
      return Object.entries(node.data)
        .map(([key, value]) => `${key}: ${formatLogicNode(value, level)}`)
        .join(`\n${indent}`);
    }
    case 'constant': {
      if (!node.data || typeof node.data !== 'object') {
        throw Error("CONSTANT node must have 'data' object");
      }
      if (node.data._type === 'Undefined') {
        return 'undefined';
      }
      return JSON.stringify(node.data.value);
    }
    case 'ifThenElse':
      if (!node.condition || !node.thenNode || !node.elseNode) {
        throw Error(
          "IF_THEN_ELSE node must have 'condition', 'thenNode', and 'elseNode'"
        );
      }
      return `${indent}If this condition is true:\n${indent}- ${formatLogicNode(
        node.condition,
        level + 1
      )}\n${indent}Then:\n${indent}- ${formatLogicNode(
        node.thenNode,
        level + 1
      )}\n${indent}Otherwise:\n${indent}- ${formatLogicNode(
        node.elseNode,
        level + 1
      )}`;

    default:
      throw Error(`Unknown node type: ${node.type}`);
  }
}

function formatInputsHumanReadable(inputs: Record<string, any>): string {
  let sections: string[] = [];

  // Handle credentials
  let credentials = Object.entries(inputs).filter(
    ([_, input]) => input.type === 'credential'
  );
  if (credentials.length > 0) {
    sections.push('Required credentials:');
    for (let [key, input] of credentials) {
      let fields = extractCredentialFields(input.data);
      let wrappedFields = fields.reduce((acc, field, i) => {
        if (i === fields.length - 1) return acc + field;
        return `${acc + field}, `;
      }, '');
      sections.push(
        `- ${key} (type: ${input.credentialType}):\n  Contains: ${wrappedFields}`
      );
    }
  }

  // Handle claims
  let claims = Object.entries(inputs).filter(
    ([_, input]) => input.type === 'claim'
  );
  if (claims.length > 0) {
    sections.push('\nClaims:');
    for (let [key, input] of claims) {
      sections.push(`- ${key}: ${input.data._type}`);
    }
  }

  // Handle constants
  let constants = Object.entries(inputs).filter(
    ([_, input]) => input.type === 'constant'
  );
  if (constants.length > 0) {
    sections.push('\nConstants:');
    for (let [key, input] of constants) {
      sections.push(`- ${key}: ${input.data._type} = ${input.value}`);
    }
  }

  return sections.join('\n');
}

function formatClaimsHumanReadable(claims: Record<string, any>): string {
  let sections = ['\nClaimed values:'];

  for (let [key, claim] of Object.entries(claims)) {
    if (claim._type === 'DynamicArray' && claim.value) {
      let values = claim.value.map((v: any) => v.value).join(', ');
      sections.push(`- ${key}:\n  ${values}`);
    } else {
      sections.push(`- ${key}: ${claim.value}`);
    }
  }

  return sections.join('\n');
}
