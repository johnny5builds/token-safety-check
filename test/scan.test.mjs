import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scanSource } from '../safety.mjs';

const rules = (src) => scanSource({ 'Token.sol': src }).map((f) => f.rule);

test('flags an owner-settable sell tax with no cap', () => {
  const r = rules(`contract T {
  function setSellFee(uint256 f) external onlyOwner {
    sellFee = f;
  }
}`);
  assert.ok(r.includes('uncapped_tax'));
  assert.ok(r.includes('fee_setter'));
});

test('does not call a capped tax setter uncapped', () => {
  const r = rules(`contract T {
  function setSellFee(uint256 f) external onlyOwner {
    require(f <= 10, "cap");
    sellFee = f;
  }
}`);
  assert.ok(!r.includes('uncapped_tax'));
});

test('flags owner balance edits', () => {
  const r = rules(`contract T {
  function adjust(address a, uint256 v) external onlyOwner {
    _balances[a] = v;
  }
}`);
  assert.ok(r.includes('owner_balance_edit'));
});

test('flags a fake renounceOwnership', () => {
  const r = rules(`contract T {
  function renounceOwnership() public override onlyOwner {
    emit OwnershipTransferred(_owner, address(0));
  }
}`);
  assert.ok(r.includes('fake_renounce'));
});

test('accepts a real renounceOwnership', () => {
  const r = rules(`contract T {
  function renounceOwnership() public override onlyOwner {
    _transferOwnership(address(0));
  }
}`);
  assert.ok(!r.includes('fake_renounce'));
});

test('flags a hidden admin in onlyOwner', () => {
  const r = rules(`contract T {
  modifier onlyOwner() {
    require(msg.sender == _owner || msg.sender == _dev);
    _;
  }
}`);
  assert.ok(r.includes('hidden_admin'));
});

test('skips audited library paths', () => {
  const f = scanSource({ '@openzeppelin/contracts/token/ERC20.sol': 'function setFee(uint x) external onlyOwner { selfdestruct(payable(msg.sender)); }' });
  assert.equal(f.length, 0);
});

test('ignores interface declarations', () => {
  assert.deepEqual(rules('interface I {\n  function setTaxFee(uint256 f) external;\n}'), []);
});
