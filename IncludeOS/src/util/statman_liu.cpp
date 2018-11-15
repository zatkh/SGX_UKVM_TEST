#include <statman>
#include <liveupdate.hpp>
#define TYPE_BUFFER 11
#define TYPE_VECTOR 12

void Statman::store(uint32_t id, liu::Storage& store)
{
  store.add_vector<Stat>(id, {m_stats.begin(), m_stats.end()});
}
void Statman::restore(liu::Restore& store)
{
  if (store.get_type() != TYPE_VECTOR) {
    assert(store.get_type() == TYPE_BUFFER);
    // discard old stats that was stored as buffer
    return;
  }
  auto stats = store.as_vector<const Stat>();

  for (auto& merge_stat : stats)
  {
    try {
      // TODO: merge here
      this->get_by_name(merge_stat.name()) = merge_stat;
    }
    catch (const std::exception& e)
    {
      this->create(merge_stat.type(), merge_stat.name()) = merge_stat;
    }
  }
}
