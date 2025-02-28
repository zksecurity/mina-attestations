import type { PresentationRequestType } from './presentation.ts';
import type { SerializedType, SerializedValue } from './serialize-provable.ts';
import type { JSONValue } from './types.ts';
import type {
  ConstantInputJSON,
  CredentialSpecJSON,
  InputJSON,
  NodeJSON,
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
      ? `\nContext:\n- Type: ${request.inputContext.type}\n- Action: ${request.inputContext.action}\n- Server Nonce: ${request.inputContext.serverNonce.value}`
      : '',
  ].join('\n');

  return formatted;
}

function printVerifierIdentity(
  type: PresentationRequestType,
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

function buildPropertyPath(node: NodeJSON): string {
  let parts: string[] = [];
  let currentNode: NodeJSON | undefined = node;

  while (currentNode?.type === 'property') {
    parts.unshift(currentNode.key);
    currentNode = currentNode.inner;
  }

  return parts.join('.');
}

function formatLogicNode(node: NodeJSON, level = 0): string {
  let indent = '  '.repeat(level);

  switch (node.type) {
    case 'and':
      if (node.inputs.length === 0) {
        return 'true';
      }
      return `${indent}All of these conditions must be true:\n${node.inputs
        .map((n) => `${indent}- ${formatLogicNode(n, level + 1)}`)
        .join('\n')}`;

    case 'or':
      return `${indent}Either:\n${indent}- ${formatLogicNode(
        node.left,
        level + 1
      )}\n${indent}Or:\n${indent}- ${formatLogicNode(node.right, level + 1)}`;

    case 'equals':
      return `${formatLogicNode(node.left)} = ${formatLogicNode(node.right)}`;

    case 'equalsOneOf': {
      let input = formatLogicNode(node.input, level);
      let options = Array.isArray(node.options)
        ? node.options.map((o) => formatLogicNode(o, level)).join(', ')
        : formatLogicNode(node.options, level);
      return `${options} contains ${input}`;
    }

    case 'lessThan':
      return `${formatLogicNode(node.left)} < ${formatLogicNode(node.right)}`;

    case 'lessThanEq':
      return `${formatLogicNode(node.left)} ≤ ${formatLogicNode(node.right)}`;

    case 'property': {
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
      return `hash(${node.inputs
        .map((n) => formatLogicNode(n, level))
        .join(', ')})`;

    case 'issuer':
      return `issuer(${node.credentialKey})`;
    case 'not':
      if (node.inner.type === 'equals') {
        return `${formatLogicNode(node.inner.left)} ≠ ${formatLogicNode(
          node.inner.right
        )}`;
      }
      return `not(${formatLogicNode(node.inner, level)})`;
    case 'add':
      return `(${formatLogicNode(node.left)} + ${formatLogicNode(node.right)})`;
    case 'sub':
      return `(${formatLogicNode(node.left)} - ${formatLogicNode(node.right)})`;
    case 'mul':
      return `(${formatLogicNode(node.left)} x ${formatLogicNode(node.right)})`;

    case 'div':
      return `(${formatLogicNode(node.left)} ÷ ${formatLogicNode(node.right)})`;

    case 'record': {
      if (Object.keys(node.data).length === 0) {
        return '{}';
      }
      return Object.entries(node.data)
        .map(([key, value]) => `${key}: ${formatLogicNode(value, level)}`)
        .join(`\n${indent}`);
    }
    case 'constant': {
      if (node.data._type === 'Undefined') {
        return 'undefined';
      }
      return node.data.value?.toString() ?? 'null';
    }
    case 'ifThenElse':
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
    case 'credential': {
      return node.credentialKey;
    }
    case 'owner': {
      return 'OWNER';
    }
    case 'issuerPublicKey': {
      return `issuerPublicKey(${node.credentialKey})`;
    }
    case 'publicInput': {
      return `publicInput(${node.credentialKey})`;
    }
    case 'verificationKeyHash': {
      return `verificationKeyHash(${node.credentialKey})`;
    }
    default:
      throw Error(`Unknown node type: ${(node satisfies never as any).type}`);
  }
}

// TODO here we assume that it makes sense to simple converting general serialized provable values to strings
// but they can be objects etc

function formatInputsHumanReadable(inputs: Record<string, InputJSON>): string {
  let sections: string[] = [];

  // Handle credentials
  let credentials = Object.entries(inputs).filter(
    (input): input is [string, CredentialSpecJSON] =>
      input[1].type === 'credential'
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
    (input): input is [string, ConstantInputJSON] =>
      input[1].type === 'constant'
  );
  if (constants.length > 0) {
    sections.push('\nConstants:');
    for (let [key, input] of constants) {
      sections.push(`- ${key}: ${input.data._type} = ${input.value}`);
    }
  }

  return sections.join('\n');
}

function formatClaimsHumanReadable(
  claims: Record<string, SerializedValue>
): string {
  let sections = ['\nClaimed values:'];

  for (let [key, claim] of Object.entries(claims)) {
    if (claim._type === 'DynamicArray' && claim.value) {
      let values = (claim.value as any[]).map((v) => v.value).join(', ');
      sections.push(`- ${key}:\n  ${values}`);
    } else {
      sections.push(`- ${key}: ${claim.value}`);
    }
  }

  return sections.join('\n');
}
