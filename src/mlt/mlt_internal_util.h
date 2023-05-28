#pragma once

namespace upw
{

// NOT multi-thread safe
template <uint32_t _NumSlots>
class MLT_ValueHistory
{
	uint64_t	_slotTimestemp[_NumSlots];
	uint64_t	_slotTotalValue[_NumSlots];
	uint32_t	_curSlotIdx = 0;
public:
	MLT_ValueHistory()
	{
		memset(_slotTimestemp, 0, sizeof(_slotTimestemp));
		memset(_slotTotalValue, 0, sizeof(_slotTotalValue));
		_curSlotIdx = 0;
	}

	void AddData(uint64_t timestamp, uint64_t value)
	{
		if(_slotTimestemp[_curSlotIdx] == 0)
		{
			_slotTimestemp[_curSlotIdx] = timestamp;
			_slotTotalValue[_curSlotIdx] = value;
		}
		else if(_slotTimestemp[_curSlotIdx] == timestamp)
		{
			_slotTotalValue[_curSlotIdx] += value;
		}
		else
		{
			_curSlotIdx = (_curSlotIdx + 1) % _NumSlots;
			_slotTimestemp[_curSlotIdx] = timestamp;
			_slotTotalValue[_curSlotIdx] = value;
		}
	}

	uint64_t GetTotalValue(uint64_t curTime, uint64_t historyLen) const
	{
		uint64_t ret = 0;
		for(uint32_t i = 0; i < _NumSlots; i++)
		{
			uint32_t slot = (_curSlotIdx + _NumSlots - i) % _NumSlots;

			// do not count the current time because it's not complete yet
			if(_slotTimestemp[slot] == curTime)
				continue;

			if(_slotTimestemp[slot] < curTime - historyLen)
				break;

			ret += _slotTotalValue[slot];
		}

		return ret;
	}

	uint64_t GetAvgValue(uint64_t curTime, uint64_t historyLen) const
	{
		return historyLen ? GetTotalValue(curTime, historyLen) / historyLen : 0;
	}
};

} // namespace upw