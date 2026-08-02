RWStructuredBuffer<uint> results : register(u0);

// Every identity below holds for any wave size, so the same shader is checked on any driver.
[numthreads(64, 1, 1)]
void main(uint3 id : SV_DispatchThreadID)
{
	const uint lanes = WaveGetLaneCount();
	const uint lane = WaveGetLaneIndex();
	uint ok = 0;
	ok |= (WaveActiveSum(1u) == WaveActiveCountBits(true)) ? 1u : 0u;
	ok |= (WavePrefixSum(1u) == lane ? 2u : 0u);
	ok |= (WaveActiveMax(lane) == lanes - 1u && WaveActiveMin(lane) == 0u) ? 4u : 0u;
	ok |= (WaveReadLaneFirst(7u) == 7u && WaveReadLaneAt(lane + 100u, 0) == 100u) ? 8u : 0u;
	ok |= (WaveActiveAllTrue(lane < lanes) && !WaveActiveAnyTrue(lane >= lanes)) ? 16u : 0u;
	ok |= (WaveIsFirstLane() == (lane == 0u)) ? 32u : 0u;
	results[id.x * 2] = ok;
	results[id.x * 2 + 1] = lanes;
}
