#pragma once

#include "gdp_base.h"

namespace upw
{

class GdpDataBuffer 
{
	GdpKey _Key;

	GdpDataPage** _Pages = nullptr;
	os::CriticalSection	_CS;

	int			_MaxPageIndex = -1;
	int			_LastPageSize = 0;
	UINT		_LatestAccessTS;
	bool		_Valid = true;

public:
	bool CheckValid() { return _Valid; }
	void RemoveData() { EnterCSBlock(_CS); _Valid = false; }
	GdpDataBuffer(const GdpKey& key) : _Key(key)
	{
		GDP_TRACE("GdpDataBuffer::GdpDataBuffer() " << GDP_BIN_TO_BASE16(_Key.Hash));
		_LatestAccessTS = os::TickCount::Get();
	}
	UINT TotalSize()
	{
		if(_LastPageSize == 0)
			return 0;
		return _MaxPageIndex* GdpDataPage::DATA_PAGESIZE + _LastPageSize;
	}
	UINT LatestUsed()
	{
		return _LatestAccessTS;
	}
	UINT ColdDataSize()
	{
		UINT all = 0;
		if(_Pages != nullptr)
		{
			for(int i = 0; i <= _MaxPageIndex; i++)
			{
				GdpDataPage* pDataPage = _Pages[i];
				if(pDataPage == nullptr)
					continue;

				if(pDataPage->Flag == GDF_COLD_NORMAL || pDataPage->Flag == GDF_COLD_FREQUENT)
				{
					if(i == _MaxPageIndex)
						all += _LastPageSize;
					else
						all += GdpDataPage::DATA_PAGESIZE;
				}

				
			}
		}

		return all;
	}
	bool ReadData(UINT offset, UINT length, LPBYTE& Data, WORD& DataLen)
	{
		EnterCSBlock(_CS);

		if(CheckValid() == false)
			return false;

		_LatestAccessTS = os::TickCount::Get();

		int PageIndex = offset / GdpDataPage::DATA_PAGESIZE;
		if(_Pages == nullptr || PageIndex > _MaxPageIndex || _Pages[PageIndex]==nullptr)
			return false;

		GdpDataPage* pDataPage = _Pages[PageIndex];

		Data = (LPBYTE)&(pDataPage->Data[offset % GdpDataPage::DATA_PAGESIZE]);
		DataLen = length; 

		if(offset >= pDataPage->DataTotalSize)
			return false;

		if(offset + length > pDataPage->DataTotalSize)
			DataLen = pDataPage->DataTotalSize - offset;

		return true;
	}
	bool SaveDataPage(GdpDataPage* pDataPage)
	{
		EnterCSBlock(_CS);

		_LatestAccessTS = os::TickCount::Get();

		if(_Pages == nullptr)
		{
			_MaxPageIndex = pDataPage->DataTotalSize / GdpDataPage::DATA_PAGESIZE;
			_LastPageSize = pDataPage->DataTotalSize % GdpDataPage::DATA_PAGESIZE;
			if(_LastPageSize == 0)
			{
				_MaxPageIndex--;
				_LastPageSize = GdpDataPage::DATA_PAGESIZE;
			}

			_Pages = _NewArray(GdpDataPage*, (_MaxPageIndex+1));

			for(int i = 0; i <= _MaxPageIndex; i++)
				_Pages[i] = nullptr;
		}

		if(_Pages[pDataPage->PageNo] == nullptr)
		{
			_Pages[pDataPage->PageNo] = pDataPage;
		}
		else
		{
			pDataPage->Release();
		}
		return true;
	}
	~GdpDataBuffer() 
	{
		EnterCSBlock(_CS);
		_Valid = false;

		if(_Pages != nullptr)
		{
			for(int i = 0; i <= _MaxPageIndex; i++)
				if(_Pages[i])
				{
					_Pages[i]->Release();
					_Pages[i] = nullptr;
				}
					

			_SafeDelArray(_Pages);
		}

		GDP_TRACE("GdpDataBuffer::~GdpDataBuffer() " << GDP_BIN_TO_BASE16(_Key.Hash));
	}

	void Execute(GdpPacketContext& context)
	{

	}
};

using DataBufferPtr					= std::shared_ptr<GdpDataBuffer>;
using DataHash_DataBufferPtr_Map	= rt::hash_map<GdpKey, DataBufferPtr, rt::_details::hash_compare_fix<GdpKey>>;

inline bool Alloc_DataBuffer(const GdpKey& key, DataBufferPtr& dst)
{
	dst = std::make_shared<GdpDataBuffer>(key);
	return true;
}

class GdpDataBufferManager
{
	DataHash_DataBufferPtr_Map	_Buffers;
	os::CriticalSection			_BufferCS;

	UINT						_LatestGCTS;		// lastest GC timestamp
public:

	GdpDataBufferManager()
	{
		_LatestGCTS = os::TickCount::Get();
	}

	bool FindData(const GdpKey& key, DataBufferPtr& lpDataBuffer, bool allocNew = false)
	{
		EnterCSBlock(_BufferCS);
		auto it = _Buffers.find(key);

		if(it != _Buffers.end())
		{
			lpDataBuffer = it->second;
			return true;
		}

		if(!allocNew)
			return false;

		Alloc_DataBuffer(key, lpDataBuffer);
		_Buffers[key] = lpDataBuffer;
		return true;
	}

	bool SaveDataPage(const GdpKey& key, GdpDataPage* pDataPage)
	{ 
		DataBufferPtr lpDataBuffer;
		
		if(FindData(key, lpDataBuffer, true) == false)
			return false;

		return lpDataBuffer->SaveDataPage(pDataPage);
	}

	bool RemoveData(const GdpKey& key)
	{ 
		DataBufferPtr lpDataBuffer;
		if(FindData(key, lpDataBuffer) == false)
			return false;

		lpDataBuffer->RemoveData();

		{
			EnterCSBlock(_BufferCS);
			_Buffers.erase(key);
		}

		return true; 
	}

	bool RemoveData(const GdpHash& hash)
	{
		EnterCSBlock(_BufferCS);
		
		auto it = _Buffers.begin();
		while( it!= _Buffers.end())
		{
			if(it->first.Hash == hash)
			{
				it->second->RemoveData();
				it = _Buffers.erase(it);
			}
			else
				it++;
		}

		return true;
	}

	bool IsHotDataCached(const GdpHash& hash)
	{
		EnterCSBlock(_BufferCS);

		for(auto& it : _Buffers)
			if(it.first.Hash == hash)
				return true;

		return false;
	}

	void RemoveAllData()
	{
		EnterCSBlock(_BufferCS);

		for(auto& kv : _Buffers)
		{
			kv.second->RemoveData();
		}

		_Buffers.clear();

	}

	bool ReadData(GdpPieceRecord& record)
	{
		DataBufferPtr lpDataBuffer;
		if(FindData(GdpKey(*record.Hash, record.Hint), lpDataBuffer) == false)
			return false;

		record.DataTotalSize = lpDataBuffer->TotalSize();

		if(record.Offset == 0 && record.Length == 0)
		{
			if(record.DataTotalSize <= GDP_BLOB_NONPAGED_MAXSIZE)
				record.Length = record.DataTotalSize;
			else
				record.Length = GDP_PACKET_FRAGMENT_SIZE;
		}

		return lpDataBuffer->ReadData(record.Offset, record.Length, record.Data, record.DataLen);
	}

	UINT ReportState()
	{
		EnterCSBlock(_BufferCS);
		UINT all = 0;
		for(auto it : _Buffers) 
		{
			all+=it.second->ColdDataSize();
		}
		return all;
	}

	void GC()
	{
		EnterCSBlock(_BufferCS);
		if(os::TickCount::Get() - _LatestGCTS < GDP_DATAPAGE_GC_INTERVAL)
			return;

		_LatestGCTS = os::TickCount::Get();


		struct Item {
			const GdpKey* key;
			UINT size;
			UINT ts;
			bool operator < (const Item& rhs) const { return this->ts < rhs.ts; }
			bool operator > (const Item& rhs) const { return this->ts > rhs.ts; }
		};

		std::vector<Item> items;
		LONGLONG total = 0;
		
		items.resize(_Buffers.size());
		int i = 0;
		for(auto& kv : _Buffers)
		{
			items[i].key = &kv.first;
			items[i].size = kv.second->TotalSize();
			items[i].ts = kv.second->LatestUsed();
			total += items[i].size;
			i++;
		}

		if(total < GDP_DATAPAGE_MEMORY_LIMIT)
			return;

		std::sort(items.begin(), items.end());

		for(auto &item : items)
		{
			_Buffers.erase(*item.key);
			total -= item.size;
			if(total < GDP_DATAPAGE_MEMORY_LIMIT)
				return;
		}
	}

};

}