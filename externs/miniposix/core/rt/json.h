#pragma once


#include "string_type_ops.h"

//////////////////////////////////////////////////////////////////////////////
// One-time json composing with zero-memory footprint
namespace rt
{
class Json;

class _JVal
{
	rt::String		__Obj;
	rt::String_Ref	_Ref;
	bool			_AsBinary;
	char			_BinLen[10];
	UINT			_BinLenSize;
	void			_SetBinLen(){ _BinLenSize = rt::_details::string_ops::itoa((UINT)_Ref.GetLength(), _BinLen); }
public:
	enum _tagVARTYPE
	{	VARTYPE_BUILTIN = 0,
		VARTYPE_STRING  = 1,
		VARTYPE_ARRAY   = 2,
		VARTYPE_OBJECT  = 3
	};
				_JVal(){ static rt::SS n("null"); _Ref = n; }
	explicit	_JVal(const rt::String_Ref& str, bool bin = false)
				{	_AsBinary = bin;
					if(bin){ _Ref = str; _SetBinLen(); }
					else _Ref = str.TrimSpace();
				}
	explicit	_JVal(rt::String_Ref& str, bool bin = false):_JVal((const rt::String_Ref&)str, bin){}
	explicit	_JVal(const rt::String& str, bool bin = false):_JVal((const rt::String_Ref&)str, bin){}
	explicit	_JVal(rt::String& str, bool bin = false):_JVal((const rt::String_Ref&)str, bin){}
	explicit	_JVal(const rt::Json& str, bool bin = false):_JVal((const rt::String_Ref&)str, bin){}
	explicit	_JVal(rt::Json& str, bool bin = false):_JVal((const rt::String&)str, bin){}
	template <template<class, class, class> class std_string, class _Traits, class _Alloc>
	explicit	_JVal(const std_string<char, _Traits, _Alloc>& str, bool bin = false):_JVal(rt::String_Ref(str), bin){}
	explicit	_JVal(LPCSTR str, bool bin = false):_JVal(rt::String_Ref(str), bin){}
	explicit	_JVal(LPSTR str, bool bin = false):_JVal(rt::String_Ref(str), bin){}
	template<typename T>
	explicit	_JVal(T& j, bool bin = false)
				{	_AsBinary = bin;
					j.ToString(__Obj);
					if(bin){ _Ref = __Obj; _SetBinLen(); }
					else _Ref = __Obj.TrimSpace();
				}
	UINT		GetLength() const 
				{	return _AsBinary?(2 + _BinLenSize + (UINT)_Ref.GetLength() + 1):
									 (_Ref.IsEmpty()?4:(UINT)_Ref.GetLength());
				}
	UINT		CopyTo(LPSTR p) const 
				{	if(_AsBinary)
					{	ASSERT(_Ref.GetLength() <= 0xffffff);
						*p = '<';
						memcpy(p+1, _BinLen, _BinLenSize);
						p += 2 + _BinLenSize;
						p[-1] = '/';
						_Ref.CopyTo(p);
						p[_Ref.GetLength()] = '>';
						return 2 + _BinLenSize + (UINT)_Ref.GetLength() + 1;
					}
					else
					{	if(_Ref.IsEmpty())
						{	*(DWORD*)p = 0x6c6c756e;
							return 4;
						}
						else return (UINT)_Ref.CopyTo(p);
					}
				}
};

namespace _details
{
	template<typename T>
	inline void _json_GetLengthPrev(T& n, UINT& l){ n._GetLength(l); }
	inline UINT _json_GetLengthPrev(LPVOID, UINT&){ return 0; }

	template<typename T>
	inline void _json_CopyPrev(T& n, LPSTR p, UINT& l){ n._CopyTo(p, l); }
	inline UINT _json_CopyPrev(LPVOID, LPSTR, UINT&){ return 0; }

	bool		_json_verify_escaped(LPCSTR p, SIZE_T len);
} // namespace _details

template<typename t_Prev, typename t_Val, int t_value_type>
struct _JVar
{
	t_Prev			prev;
	rt::String_Ref	tagname;
	t_Val			value;

	void	_GetLength(UINT& len) const
			{	_details::_json_GetLengthPrev(prev, len);
				if(!IsGhost())
				{	if(len)len++;
					len += (UINT)tagname.GetLength() + 3;
					len += (UINT)value.GetLength() + (_JVal::VARTYPE_STRING == t_value_type?2:0);
				}
			}
	void	_CopyTo(LPSTR p, UINT& len) const
			{	_details::_json_CopyPrev(prev, p, len);
				if(!IsGhost())
				{	if(len)
					{	len++;	p += len;
						*(p-1) = ',';
					}
					int l;
					*p++='"'; p += (l = (UINT)tagname.CopyTo(p)); *p++='"';
					*p++=':'; len += l + 3;
					if(_JVal::VARTYPE_STRING == t_value_type)
					{	*p++='"';
						l = (UINT)value.CopyTo(p);
						ASSERT(_details::_json_verify_escaped(p, l));
						p += l;
						*p++='"';
						len += l + 2;
					}
					else{ len += (UINT)value.CopyTo(p); }
				}
			}
	template<typename t_V>
	_JVar(const rt::String_Ref& name, t_V& v):tagname(name), value(v){}
	_JVar(){}
	template<typename Prev, typename t_V>
	_JVar(Prev& n, const rt::String_Ref& name, t_V& v):tagname(name), value(v), prev(n){}

	bool	IsGhost() const { return tagname.IsEmpty(); }
	UINT	GetLength() const
			{	UINT len = 0;	_GetLength(len);
				if(len)return len + 2;
				return 2;
			}
	UINT	CopyTo(LPSTR p) const
			{	*p++ = '{';
				UINT len = 0;
				_CopyTo(p, len);
				if(len){ p+=len; *p = '}'; return len + 2; }
				*p = '}';
				return 2;
			}
	void	ToString(rt::String& out) const
			{	VERIFY(out.SetLength(GetLength()));
				out.SetLength(CopyTo(out.Begin()));
			}

	template<typename t_right, int t_right_vt>
	auto operator , (const _JVar<LPVOID, t_right, t_right_vt>& right) const
	{	
		return _JVar< _JVar<t_Prev,t_Val,t_value_type>, t_right, t_right_vt>
			   ((const _JVar<t_Prev,t_Val,t_value_type>&)*this, right.tagname, right.value);
	}

	template<typename t_right_prev, typename t_right, int t_right_vt>
	auto operator , (const _JVar<t_right_prev, t_right, t_right_vt>& right) const
	{	
		return _JVar< _JVar<t_Prev,t_Val,t_value_type>, t_right, t_right_vt>
			   ((const _JVar<t_Prev,t_Val,t_value_type>&)*this, right.tagname, right.value), right.prev;
	}

	template<typename STRING>
	void _AppendValueToString(STRING& str) const
	{
		if(_JVal::VARTYPE_STRING != t_value_type){ str += value; }
		else 
		{	str += '"';
#if defined(PLATFORM_DEBUG_BUILD)
			SIZE_T org = str.GetLength();
			str += value;
			ASSERT(_details::_json_verify_escaped(&str[org], str.GetLength() - org));
#else
			str += value;
#endif
			str += '"'; 
		}
	}
};

namespace _details
{
	template<typename T, typename STRING>
	static void _AppendJsonValueToString(const T& v, STRING& str);
} // namespace _details

template<typename t_String = rt::StringFixed<1024>>  // or StringFixed<LEN>
class _JArray
{
	t_String	_buf;
public:
	_JArray(){ _buf = "["; }
	template<typename T>
	void	Append(const T& jval)
			{	if(_buf.GetLength() != 1){ _buf += ',';	}
				_details::_AppendJsonValueToString(jval, _buf);
			}

	UINT	GetLength() const { return (UINT)(_buf.GetLength() + 1); }
	UINT	CopyTo(LPSTR p) const 
			{	_buf.CopyTo(p);
				p[_buf.GetLength()] = ']';
				return (UINT)(_buf.GetLength()+1);
			}
};

#define J_EXPR_CONNECT_OP(type, type_in, vt)					\
_JVar<LPVOID, type, vt>											\
operator = (type_in p)											\
{	if(tagname.IsEmpty())										\
	{	static type __empty_p; 									\
		return _JVar<LPVOID, type, vt>(tagname, __empty_p);		\
	} else { return _JVar<LPVOID, type, vt>(tagname, p); }		\
}																\

struct _JTag
{	
	template<typename t_Obj>
	struct _O
	{	const t_Obj* _Obj;
		UINT	GetLength() const { ASSERT(_Obj); return (UINT)_Obj->GetLength(); }
		UINT	CopyTo(LPSTR p) const { ASSERT(_Obj); return (UINT)_Obj->CopyTo(p); }
		FORCEINL		_O(const t_Obj& x):_Obj(&x){}
		FORCEINL		_O(){ _Obj = nullptr; }
	};

	rt::String_Ref	tagname;
	_JTag(){}
	_JTag(const rt::String_Ref& name):tagname(name){}

	J_EXPR_CONNECT_OP(String_Ref,					const String_Ref&	, _JVal::VARTYPE_STRING)
	J_EXPR_CONNECT_OP(String_Ref,					const char*			, _JVal::VARTYPE_STRING)
	J_EXPR_CONNECT_OP(tos::S_<MARCO_CONCAT(1,2)>,	char				, _JVal::VARTYPE_STRING)
	J_EXPR_CONNECT_OP(tos::S_<MARCO_CONCAT(1,12)>,	int					, _JVal::VARTYPE_BUILTIN)
	J_EXPR_CONNECT_OP(tos::S_<MARCO_CONCAT(1,7)>,	bool				, _JVal::VARTYPE_BUILTIN)
	J_EXPR_CONNECT_OP(tos::S_<MARCO_CONCAT(1,12)>,	unsigned int		, _JVal::VARTYPE_BUILTIN)
	J_EXPR_CONNECT_OP(tos::S_<MARCO_CONCAT(1,25)>,	LONGLONG			, _JVal::VARTYPE_BUILTIN)
	J_EXPR_CONNECT_OP(tos::S_<MARCO_CONCAT(1,25)>,	ULONGLONG			, _JVal::VARTYPE_BUILTIN)
#if defined(PLATFORM_WIN)
	J_EXPR_CONNECT_OP(tos::S_<MARCO_CONCAT(1,12)>,	long				, _JVal::VARTYPE_BUILTIN)
	J_EXPR_CONNECT_OP(tos::S_<MARCO_CONCAT(1,12)>,	unsigned long		, _JVal::VARTYPE_BUILTIN)
#endif
	J_EXPR_CONNECT_OP(tos::S_<MARCO_CONCAT(1,32)>,	float				, _JVal::VARTYPE_BUILTIN)
	J_EXPR_CONNECT_OP(tos::S_<MARCO_CONCAT(1,64)>,	double				, _JVal::VARTYPE_BUILTIN)
	J_EXPR_CONNECT_OP(_O<_JVal>,					const _JVal& 		, _JVal::VARTYPE_OBJECT)

	auto operator = (const Json& p)
	{	return _JVar<LPVOID, const rt::String_Ref&, _JVal::VARTYPE_OBJECT>(tagname, (const rt::String_Ref&)p);
	}
	template<typename prev, typename type, int val_type>
	auto operator = (const _JVar<prev, type, val_type>& p)
	{	return _JVar<LPVOID, _O<const _JVar<prev, type, val_type>>, _JVal::VARTYPE_OBJECT>(tagname, p);
	}
	template<typename T>
	auto operator = (const _JArray<T>& p)
	{	return _JVar<LPVOID, _O<const _JArray<T>>, _JVal::VARTYPE_ARRAY>(tagname, p);
	}
	template<typename t_Left, typename t_Right>
	auto operator = (const _SE<t_Left,t_Right>& p)
	{	return _JVar<LPVOID, _O<const _SE<t_Left,t_Right>>, _JVal::VARTYPE_STRING>(tagname, p);
	}
};

#undef J_EXPR_CONNECT_OP

template<typename LEFT, typename T, int VAL_TYPE>
inline auto operator + (const String_Ref& left, const _JVar<LEFT, T, VAL_TYPE>& right)
{	return _SE<String_Ref, _JVar<LEFT, T, VAL_TYPE>>( (left), (right) );
}
template<typename t_Left, typename t_Right, typename LEFT, typename T, int VAL_TYPE>
inline auto operator + (const _JVar<LEFT, T, VAL_TYPE>& p, const _SE<t_Left,t_Right>& x)	
{	return _SE<_JVar<LEFT, T, VAL_TYPE>, _SE<t_Left,t_Right>>(p,x);
}
template<typename t_Left, typename t_Right, typename LEFT, typename T, int VAL_TYPE>
inline auto operator + (const _SE<t_Left,t_Right>& x, const _JVar<LEFT, T, VAL_TYPE>& p)	
{	return _SE<_SE<t_Left,t_Right>, _JVar<LEFT, T, VAL_TYPE>>(x, p);
}

namespace _details
{
	template<typename T, typename STRING>
	static	void _AppendJsonValueToString(const T& v, STRING& str)
	{	static rt::_JTag _t("_");
		(_t = v).template _AppendValueToString<STRING>(str);
	}
} // namespace _details
} // namespace rt

#define J(x)					rt::_JTag(#x)
#define J_IF(cond, definition)	((cond) ? (definition) : decltype(definition)())
#define JB(x)					(rt::_JVal((x), true))		///< Json Binary

template<typename T>
inline void _JA(rt::_JArray<>& a, T&& t){ a.Append(t); }
template<typename T, typename... Ts>
inline void _JA(rt::_JArray<>& a, T&& t, Ts&& ... args){ a.Append(t); _JA(a, args...); }
template<typename... Ts>
inline rt::_JArray<> JA(Ts&& ... args){	rt::_JArray<> a; _JA(a, args...); return a; }
template<>
inline rt::_JArray<> JA() { return {}; }

namespace rt
{
//////////////////////////////////////////////
// Increamental json composing
class Json
{
protected:
	rt::String		_String;
	bool			IsEndsWith(int c){ return !_String.IsEmpty() && _String.Last() == c; }

public:
	class _Appending
	{	protected:	Json* _pJson;
		public:		_Appending(Json& j):_pJson(&j){}
					operator Json& (){ return *_pJson; }
					auto& StringForAppending(){ return _pJson->_String; }
	};
	struct _AppendingKeyedValue: public _Appending
	{	friend class Json;
		Json* operator ->(){ return _pJson; }
		_AppendingKeyedValue(_AppendingKeyedValue&& x):_Appending(x){ x._pJson = nullptr; }
		~_AppendingKeyedValue(){ if(_pJson)_pJson->_String += '}'; }
		template<typename T>
		void operator << (const T& json_str){ *_pJson << json_str; }
	protected:
		_AppendingKeyedValue(Json& j, const rt::String_Ref& key);
	};
	struct _MergingObject: public _Appending
	{	friend class Json;
		Json* operator ->(){ return _pJson; }
		SIZE_T	_StartPos;
		_MergingObject(_MergingObject&& x):_Appending(x){ _StartPos = x._StartPos; x._pJson = nullptr; }
		~_MergingObject();
		template<typename T>
		void operator << (const T& json_str){ *_pJson << json_str; }
	protected:
		_MergingObject(Json& j);
	};
	struct _AppendingElement: public _Appending
	{	friend class Json;
		Json* operator ->(){ return _pJson; }
		_AppendingElement(_AppendingElement&& x):_Appending(x){ x._pJson = nullptr; }
		~_AppendingElement(){ if(_pJson)_pJson->_String += ']';	}
		template<typename T>
		void operator << (const T& json_str){ *_pJson << json_str; }
	protected:
		_AppendingElement(Json& j);
	};
	struct _AppendingArray: public _Appending
	{	friend class Json;
		Json* operator ->(){ return _pJson; }
		SIZE_T	_StartPos;
		_AppendingArray(_AppendingArray&& x):_Appending(x){ _StartPos = x._StartPos; x._pJson = nullptr; }
		~_AppendingArray();
		template<typename T>
		void operator << (const T& json_str){ *_pJson << json_str; }
	protected:
		_AppendingArray(Json& j);
	};
	struct _WritingStringEscaped: public _Appending
	{	friend class Json;
		_WritingStringEscaped(_AppendingArray&& x):_Appending(x){ x._pJson = nullptr; }
		~_WritingStringEscaped(){ if(_pJson)_pJson->_String += '"'; }
		operator	rt::String& (){ return _pJson->_String; }
		auto&		String(){ return _pJson->_String; }
		template<typename T>
		void operator << (const T& json_str){ *_pJson << json_str; }
	protected:
		_WritingStringEscaped(Json& j);
	};
	struct _WritingStringAtKey: public _Appending
	{	friend class Json;
		Json* operator ->(){ return _pJson; }
		_WritingStringAtKey(_AppendingKeyedValue&& x):_Appending(x){ x._pJson = nullptr; }
		~_WritingStringAtKey(){	if(_pJson){ _pJson->_String += '"'; _pJson->_String += '}'; }}
		operator	rt::String& (){ return _pJson->_String; }
		auto&		String(){ return _pJson->_String; }
		template<typename T>
		void operator << (const T& json_str){ *_pJson << json_str; }
	protected:
		_WritingStringAtKey(Json& j, const rt::String_Ref& key);
	};

public:
	operator const rt::String&() const { return _String; }
	operator const rt::String_Ref&() const { return _String; }
	auto&	GetInternalString(){ return _String; }
	auto&	GetInternalString() const { return _String; }

	SIZE_T	GetLength() const { return _String.GetLength(); }
	SIZE_T	CopyTo(char* p) const { return _String.CopyTo(p); }
	LPCSTR	Begin() const { return _String.Begin(); }
	auto&	Empty(){ _String.Empty(); return *this; }

	template<typename T>
	void	Object(const T& json_str){ _details::_AppendJsonValueToString(json_str, _String); }
	auto&	Object(){ _String += '{'; _String += '}'; return *this; }
	auto&	Array(){ _String += '['; _String += ']'; return *this; }
	auto&	Boolean(bool v){ _String += v?rt::SS("true"):rt::SS("false"); return *this; }
	auto&	Null(){ _String += rt::SS("null"); return *this; }
	Json&	String(const rt::String_Ref& s);
	template<typename T>
	auto&	Number(T n){ _String += rt::tos::Number(n); return *this; }
	template<typename StrExp>
	auto&	StringEscaped(const StrExp& s){ _String += '"'; _String += s; _String += '"'; return *this; }
	Json&	Binary(const void* data, uint32_t size); // as base64 string
	[[nodiscard]]
	auto	ScopeMergingObject(){ return _MergingObject(*this); }
	template<typename P, typename V, int VT>
	auto&	MergeObject(const _JVar<P,V,VT>& json){ _MergingObject(*this)._pJson->_String += json; return *this; }
	Json&	MergeObject(const rt::String_Ref& json_str);

	[[nodiscard]]
	auto	ScopeAppendingKey(const rt::String_Ref& key){ return _AppendingKeyedValue(*this, key); }
	template<typename T>
	auto&	AppendKey(const rt::String_Ref& key, const T& json_value) // value should be valid json string, or numeric types
			{	ASSERT(IsEndsWith('}'));
				_details::_AppendJsonValueToString(json_value, _AppendingKeyedValue(*this, key)._pJson->_String);
				return *this;
			}
	Json&	AppendKeyWithString(const rt::String_Ref& key, const rt::String_Ref& string); // value is a string, will be escaped
	Json&	AppendKeyWithBinary(const rt::String_Ref& key, const rt::String_Ref& data); // value is a binary data, will be base64 encoded

	[[nodiscard]]
	auto	ScopeAppendingElement(){ return _AppendingElement(*this); }
	template<typename T>
	auto&	AppendElement(const T& json_value)
			{	ASSERT(IsEndsWith(']'));
				_details::_AppendJsonValueToString(json_value, _AppendingElement(*this)._pJson->_String);
				return *this;
			}

	[[nodiscard]]
	auto	ScopeMergingArray(){ return _AppendingArray(*this); }
	template<typename T>
	auto&	MergeArray(const T& json_array){ _AppendingArray(*this)._pJson->_String += json_array; return *this; }
	template<typename P, typename V, int VT>
	auto&	operator << (const _JVar<P,V,VT>& json){ return IsEndsWith('}')?MergeObject(json):AppendElement(json); }

	template<typename T>
	auto&	operator << (const T& x){ return AppendElement(x); }

	[[nodiscard]]
	auto	ScopeWritingStringEscaped(){ return _WritingStringEscaped(*this); }
	[[nodiscard]]
	auto	ScopeWritingStringEscapedAtKey(const rt::String_Ref& key){ return _WritingStringAtKey(*this, key); }
	void	AppendStringEscaped(const rt::String_Ref& s){ _String += s; }
	void	AppendString(const rt::String_Ref& s);
};



//////////////////////////////////////////////////////////////////////////////
// Parsing Json Data
typedef enum _tagJsonType
{
	JSON_STRING,
	JSON_NUMBER,
	JSON_BOOL,
	JSON_NULL,
	JSON_OBJECT,
	JSON_ARRAY,
	JSON_BINARY,
	JSON_CORRUPTED
} JsonType;

class JsonKeyValuePair
{
	friend class JsonObject;
	rt::String_Ref	_Key;
	rt::String_Ref	_Value;

public:
	static JsonType GetValueType(const rt::String_Ref& Value);

public:
	const rt::String_Ref&	GetKey() const { return _Key; }
	const rt::String_Ref&	GetValue() const { return _Value; }
	rt::String_Ref			GetValueRaw() const;
	JsonType				GetValueType() const { return GetValueType(_Value); }
	void					Empty(){ _Key.Empty(); _Value.Empty(); }
	bool					IsEmpty() const { return _Key.IsEmpty() || _Value.IsEmpty(); }

	template<typename T>
	T						GetValueAs() const { return GetValueAs<T>(0); }
	template<typename T>
	T						GetValueAs(T default_val) const
							{	rt::String_Ref s = GetValue();
								if(!s.IsEmpty())s.ToNumber(default_val); 
								return default_val;
							}
};
	
template<>
inline bool JsonKeyValuePair::GetValueAs<bool>(bool default_val) const
{	rt::String_Ref s = GetValue();
	if(!s.IsEmpty()){ return s[0] == 'T' || s[0] == 't'; }
	return default_val;
}


class JsonObject
{
	friend class JsonArray;
	friend class JsonBeautified;
	rt::String_Ref	_Doc;
protected:
	static const LPCSTR _skip_whitespace(LPCSTR p, LPCSTR end){ while(p < end && *p<=' ' && *p>=0)p++; return p; }
	static const LPCSTR _scan_text(LPCSTR p, LPCSTR end){ while(p < end && _is_text(*p))p++; return p; }
	static const LPCSTR _seek_char(LPCSTR p, LPCSTR end, char c){ while(p < end && *p!=c)p++; return p; }
	static const void	_cook_raw_value(LPCSTR& p, LPCSTR& tail)
						{	if(*p == '"' || *p == '\''){ p++; tail--; } // string
							else if(*p == '<'){	p+=2; while(*p != '/'){ p++; ASSERT(p<tail); } p++;	tail--; }  // binary
						}
	static const bool   _is_text(int c)
						{	static const rt::CharacterSet sep(rt::SS("\x7\x9\xa\xb\xc\xd '\",:{}[]"));
							return !sep.Has(c); // c<0 || ( c>' ' && c!='\'' && c!='"' && c!=',' && c!=':' && c!='{' && c!='}'); 
						}
	static const LPCSTR _seek_char_escape(LPCSTR p, LPCSTR end, char c)
						{	for(;p < end;p++)
							{	if(*p==c)
								{	LPCSTR s = p-1;
									for(;*s == '\\';s--);
									if(((int)(s-p))&1)return p;
								}
							}
							return end;
						}
	static const int   _match_closure(int c)
						{	if(c == '"' || c == '\'')return c;
							else if(c == '[')return ']';
							else if(c == '{')return '}';
							else return 0;
						}
	static LPCSTR		_seek_json_object_closure(LPCSTR p, LPCSTR end);
	LPCSTR				_LocateValue(const rt::String_Ref& xpath, bool bDoNotSplitDot = false) const;

public:
	JsonObject(){};
	JsonObject(LPCSTR str, UINT length){ Attach(str, length); }
	JsonObject(const rt::String_Ref& doc){ Attach(doc); }

	const rt::String_Ref& GetString() const { return _Doc; }
	operator const rt::String_Ref () const { return _Doc; }

	void			Attach(LPCSTR str, UINT length){ Attach(rt::String_Ref(str, length)); }
	void			Attach(const rt::String_Ref& doc){	SSIZE_T s = doc.FindCharacter('{');	if(s>=0)_Doc = doc.SubStr(s); }
	rt::String_Ref	GetValueRaw(const rt::String_Ref& xpath, const rt::String_Ref& default_val = rt::String_Ref(), bool bDoNotSplitDot = false) const;	// xxx.yyy.zzz
	rt::String_Ref	GetValueRaw(const rt::String_Ref& xpath, bool& p_exist, bool bDoNotSplitDot = false) const;	// xxx.yyy.zzz
	rt::String_Ref	GetValue(const rt::String_Ref& xpath, const rt::String_Ref& default_val = rt::String_Ref(), bool bDoNotSplitDot = false) const;	// xxx.yyy.zzz
	rt::String_Ref	GetValue(const rt::String_Ref& xpath, bool& p_exist, bool bDoNotSplitDot = false) const;	// xxx.yyy.zzz
	bool			IsEmpty() const { return _Doc.IsEmpty(); }
	bool			IsEmptyObject() const;
	bool			GetNextKeyValuePair(JsonKeyValuePair& kvp) const;

	template<typename T>
	T				GetValueAs(const rt::String_Ref& xpath, T default_val) const
					{	rt::String_Ref s = GetValue(xpath);
						if(!s.IsEmpty())s.ToNumber(default_val);
						return default_val;
					}
	template<typename T>
	T				GetValueAs(const rt::String_Ref& xpath) const { return GetValueAs<T>(xpath, 0); }
	template<typename T>
	bool			LoadValueAs(const rt::String_Ref& xpath, T &out_v) const
					{
						rt::String_Ref data = GetValue(xpath);
						if (data.IsEmpty())
							return false;
						return data.ToNumber<T, 10, false, '.', ',', true>(out_v) == (int)data.GetLength();
					}
	bool			LoadValue(const rt::String_Ref& xpath, rt::String_Ref& out_v) const
					{	bool bExist;
						rt::String_Ref data = GetValue(xpath, bExist);
						if (!bExist)
							return false;
						out_v = data;
						return true;
					}
	static void		RemoveKeys(const rt::String_Ref& source, const rt::String_Ref& keys_to_exclude, rt::String& removed);

	// Derive: create a new json with overrided keys from another json string, duplicated keys will be updated, the rest remains the same
	template<typename T1,typename T2,int VT>
	void			Derive(const rt::_JVar<T1,T2,VT>& sub, rt::String& derived, bool append = false) const { Override(_Doc, sub, derived, append); }
	void			Derive(const rt::String_Ref& sub, rt::String& derived, bool append = false) const { Override(_Doc, sub, derived, append); }
	void			Derive(const rt::String_Ref& key, const rt::String_Ref& val_raw, rt::String& derived, bool append = false) const { Override(_Doc, key, val_raw, derived, append); }
	// Override: create a new json with overrided keys from another json string, duplicated keys will be updated, the rest remains the same
	template<typename T1,typename T2,int VT>
	static void		Override(const rt::String_Ref& base, const rt::_JVar<T1,T2,VT>& sub, rt::String& derived, bool append = false){ Override(base, rt::String(sub), derived, append); }
	static void		Override(const rt::String_Ref& base, const rt::String_Ref& sub, rt::String& derived, bool append = false);
	static void		Override(const rt::String_Ref& base, const rt::String_Ref& key, const rt::String_Ref& val_raw, rt::String& derived, bool append = false);

	//rt::String		GetValueUnescaped(const rt::String_Ref& xpath, const rt::String_Ref& default_val = rt::String_Ref(), bool bDoNotSplitDot = false) const // **Do Not** assign return to a String_Ref
	//				{	return JsonUnescapeString(GetValue(xpath, default_val, bDoNotSplitDot));
	//				}
	//rt::String		GetValueUnescaped(const rt::String_Ref& xpath, bool& p_exist, bool bDoNotSplitDot = false) const // **Do Not** assign return to a String_Ref
	//				{	return JsonUnescapeString(GetValue(xpath, p_exist, bDoNotSplitDot));
	//				}

	static void		UnescapeStringValue(const rt::String_Ref& in, rt::String& val_out);
};
template<>
inline bool JsonObject::GetValueAs<bool>(const rt::String_Ref& xpath, bool default_val) const
{	rt::String_Ref s = GetValue(xpath);
	if(!s.IsEmpty()){ return s[0] != 'F' && s[0] != 'f' && s[0] != '0'; }
	return default_val;
}
template<>
inline bool JsonObject::LoadValueAs(const rt::String_Ref& xpath, rt::String_Ref& out_v) const
{
	return LoadValue(xpath, out_v);
}

class JsonArray
{
	rt::String_Ref	_Doc;
public:
	JsonArray(const rt::String_Ref& doc);
	bool IsEmpty() const { return _Doc.IsEmpty(); }
	bool GetNextObjectRaw(JsonObject& obj) const { return GetNextObjectRaw(obj._Doc); }
	bool GetNextObjectRaw(rt::String_Ref& obj) const;
	bool GetNextObject(rt::String_Ref& obj) const;
	SIZE_T GetSize() const;

	template<typename t_Num>
	UINT CopyNumbers(t_Num* pDest, SIZE_T DestLen) const // return actual number of numbers copied
	{	
		SIZE_T i = 0;
		rt::String_Ref item;
		for(; i<DestLen; i++)
		{	if(GetNextObject(item))
			{	item.ToNumber(pDest[i]);
			}else break;
		}
		return (UINT)i;
	}
};


//////////////////////////////////////////////////////////////////////////////
// Misc 
class JsonBeautified: public rt::String
{
	bool _bNewLineAsCRLN = false;
	int _Indent = 0;
	int _Line_max = 0;

	void _AppendSpace(UINT count){ memset(Extend(count), ' ', count); }
	void _AppendAsSingleLine(const rt::String_Ref& doc);
	void _Beautify(const rt::String_Ref& json_string, bool newline, int depth, int line_remain);

public:
	JsonBeautified(bool newline_crln = false){ _bNewLineAsCRLN = newline_crln; }
	JsonBeautified(const rt::String_Ref& json_string, int indent = 3, int line_remain = 80){ Beautify(json_string, indent, line_remain); }
	void Beautify(const rt::String_Ref& json_string, int indent = 3, int line_remain = 80);
};

class JsonEscapeString: public rt::String
{
public:
	JsonEscapeString(const rt::String_Ref& c_string, bool add_quote = false);
	static void Concat(const rt::String_Ref& input, rt::String& in_out);
};

class JsonUnescapeString: public rt::String
{
public:
	JsonUnescapeString(const rt::String_Ref& json_string)
	{	
		JsonObject::UnescapeStringValue(json_string, *this);
	}
};

} // namespace rt